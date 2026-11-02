import argparse
import asyncio
import csv
import json
import random
import subprocess
import sys
import time
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRIPT_DIR = Path(__file__).resolve().parent
PYTHON_DIR = SCRIPT_DIR.parents[1]
REPO_ROOT = SCRIPT_DIR.parents[2]
sys.path.insert(0, str(SCRIPT_DIR.parent))

import common

from centers import bulk_generate, encrypt_share_for_center
from config import settings
from drand_client import DrandError, fetch_round, verify_round_published
from ipfs_client import IPFSError
from manifest import build_and_sign, verify as verify_manifest
from reconstruct import (
    ReconstructError,
    _cat_any_node,
    combine_shares_to_pdf,
    fetch_and_decrypt_one_shard,
)
from shamir import reconstruct as shamir_reconstruct
from shamir import split as shamir_split
from vajra_coordinator import coordinate


N = 10
K = 8
RESULTS_FILE = SCRIPT_DIR / "raw_results.csv"
DUMMY_EXAM = b"%PDF-1.4\n%vajra-exp07-failure-testing-dummy-exam\n%%EOF"

CHAIN_HASH = settings.drand_chain_hash
TARGET_ROUND = 1
PUBLISH_TIME = settings.drand_genesis + settings.drand_period * TARGET_ROUND

results = []
RUN_INFO: dict = {}
BACKENDS: dict = {}
DRAND_MODE = "mock"

def find_vajra_binary():
    """Return an available release-mode Vajra binary, or `None`."""
    for name in ('vajra', 'vajra.exe'):
        candidate = REPO_ROOT / 'rust' / 'target' / 'release' / name
        if candidate.exists():
            return candidate
    return None


VAJRA_BIN = find_vajra_binary()


def prepare_real_puzzle(vajra_binary, workdir):
    from drand_client import derive_aad

    puzzle_path = workdir / "puzzle.json"
    secret_path = workdir / "secret.json"
    exam_path = workdir / "dummy_exam.pdf"
    locked_path = workdir / "locked.json"
    exam_path.write_bytes(DUMMY_EXAM)

    aad_hex = derive_aad(TARGET_ROUND, CHAIN_HASH).hex()

    gen = subprocess.run(
        [str(vajra_binary), 'generate', '--time', '1', '--puzzle-out', str(puzzle_path), '--secret-out', str(secret_path)],
        capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if gen.returncode != 0: raise RuntimeError(f"`vajra generate` failed: output: {gen.stdout[-1000:]} error: {gen.stderr[-1000:]}")

    lock = subprocess.run(
        [str(vajra_binary), 'lock', '--puzzle', str(puzzle_path), '--secret', str(secret_path), '--input', str(exam_path),
         '--output', str(locked_path), '--aad-hex', str(aad_hex)], capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if lock.returncode != 0: raise RuntimeError(f'`vajra lock` failed output: {lock.stdout[-1000:]} error: {lock.stderr[-1000:]}')

    return puzzle_path.read_bytes(), locked_path.read_bytes()


def get_backend(node_count: int):
    for other in BACKENDS.values():
        other.reset()
    return BACKENDS[str(node_count)]


async def build_instance(ipfs, puzzle_bytes: bytes, locked_bytes: bytes, *, n: int = N, k: int = K, isolate_control: bool = False):
    from drand_client import derive_aad

    registry, keypairs = bulk_generate(n, id_prefix='CENTER')
    aad = derive_aad(TARGET_ROUND, CHAIN_HASH)

    data_key = secrets.token_bytes(32)
    shares = shamir_split(data_key, n, k)
    encrypted = [encrypt_share_for_center(s, registry[i].pubkey) for i, s in enumerate(shares)]

    nonce = secrets.token_bytes(12)
    payload = AESGCM(data_key).encrypt(nonce, locked_bytes, aad)

    puzzle_cid = await ipfs.add_bytes(puzzle_bytes, 'puzzle.json', node_index=0, control=isolate_control)
    payload_cid = await ipfs.add_bytes(payload, 'payload.bin', node_index=0, control=isolate_control)

    shard_cids = []
    for i, enc in enumerate(encrypted):
        node_idx = i % ipfs.node_count
        cid = await ipfs.add_json({'center_id': registry[i].id, **enc.to_dict()}, f'shard_{i:03d}.json', node_index=node_idx)
        shard_cids.append({'cid': cid, 'node_index': node_idx})

    manifest = build_and_sign(
        n=n, k=k, puzzle_cid=puzzle_cid, payload_cid=payload_cid, nonce_hex=nonce.hex(),
        shard_cids=shard_cids,
        centers=[{'index': i, 'id': r.id, 'pubkey': r.pubkey} for i, r in enumerate(registry)],
        drand={
            'chain_hash': CHAIN_HASH, 'target_round': TARGET_ROUND, 'publish_time': PUBLISH_TIME,
        },
    )
    manifest_cid = await ipfs.add_json(manifest, 'manifest.json', node_index=0, control=isolate_control)

    return {
        'ipfs': ipfs,
        'manifest_cid': manifest_cid,
        'manifest': manifest,
        'registry': registry,
        'keypairs': keypairs,
        'aad': aad,
    }


async def try_centre(instance: dict, idx: int):
    ipfs = instance['ipfs']
    try: manifest = await ipfs.cat_json(instance['manifest_cid'])
    except IPFSError: return None
    if not verify_manifest(manifest): return None
    _, sk_hex = instance['keypairs'][idx]
    try: return await fetch_and_decrypt_one_shard(manifest, idx, sk_hex, ipfs)
    except ReconstructError: return None


async def gather_available(instance: dict, n: int) -> tuple[list[int], list[bytes]]:
    idxs, shares = [], []
    for i in range(n):
        share = await try_centre(instance, i)
        if share is not None:
            idxs.append(i)
            shares.append(share)
    return idxs, shares


async def reconstruct_data_key_layer(manifest: dict, plaintext_shares: list[bytes], ipfs, aad: bytes):
    k_val = int(manifest['k'])
    if len(plaintext_shares) < k_val: raise ReconstructError(f'Need >= {k_val} plaintext shares to reconstruct, got {len(plaintext_shares)}')
    seen_x: set[int] = set()
    for s in plaintext_shares:
        if s[0] in seen_x: raise ReconstructError(f'Duplicate Shamir x-coord {s[0]} among submitted shares')
        seen_x.add(s[0])
    try: data_key = shamir_reconstruct(plaintext_shares, expected_threshold=k_val)
    except Exception as e: raise ReconstructError(f'Shamir reconstruction failed: {e}') from e
    payload_bytes = await _cat_any_node(manifest['payload_cid'], ipfs)
    nonce = bytes.fromhex(manifest['nonce'])
    try: AESGCM(data_key).decrypt(nonce, payload_bytes, aad)
    except Exception as e: raise ReconstructError('Outer AES-GCM decryption failed. Either the submitted shares are wrong/insufficient or the payload has been tampered with.') from e


async def attempt_pipeline(manifest: dict, plaintext_shares: list[bytes], ipfs, aad: bytes):
    if VAJRA_BIN is not None:
        try:
            pdf_bytes = await  combine_shares_to_pdf(manifest, plaintext_shares, ipfs, VAJRA_BIN, skip_drand_check=True)
            return True, f'reconstructed {len(pdf_bytes)}-byte PDF via real `vajra solve`'
        except ReconstructError as e: return False, str(e)
    try:
        await reconstruct_data_key_layer(manifest, plaintext_shares, ipfs, aad)
        return True, 'data_key + outer AES-GCM recovered correctly (vajra binary not found — solve step skipped)'
    except ReconstructError as e: return False, str(e)


def record(scenario: str, case: str, repetition: int, expected: str, actual: str, notes: str):
    results.append(
        {
            'scenario': scenario,
            'case': case,
            'repetition': repetition,
            'n': N,
            'k': K,
            'expected_result': expected,
            'actual_result': actual,
            'passed': expected == actual,
            'notes': notes,
            **RUN_INFO,
        }
    )
    tick = 'OK' if expected == actual else "!!"
    print(f'{tick}[{scenario}/{case} #{repetition}] expected={expected} actual={actual}')


async def scenario_manifest_control_spof():
    print("[1-2] Manifest/payload/puzzle placement (node 0, per main.py's real layout)")
    for label, down in (('baseline_all_up', set()), ('primary_node_down', {0})):
        for rep in range(1, 4):
            ipfs = get_backend(3)
            inst = await build_instance(ipfs, PUZZLE_BYTES, LOCKED_BYTES, isolate_control=False)
            ipfs.set_down(down)
            idxs, shares = await gather_available(inst, N)
            expected = 'Success' if len(idxs) >= K else 'Fail'
            ok, note = await attempt_pipeline(inst['manifest'], shares, ipfs, inst['aad'])
            actual = 'Success' if ok else 'Fail'
            record('manifest_control_placement', label, rep, expected, actual, f'{len(idxs)}/{N} centres could even reach the manifest+their shard; {note}')


async def scenario_shard_granularity_3nodes():
    print('[3] Shard availability under a single non-primary IPFS node outage (3-node deploy)')
    for rep in range(1, 4):
        down_node = random.choice([1, 2])
        ipfs = get_backend(3)
        inst = await build_instance(ipfs, PUZZLE_BYTES, LOCKED_BYTES, isolate_control=False)
        ipfs.set_down({down_node})
        idxs, shares = await gather_available(inst, N)
        expected = 'Success' if len(idxs) >= K else 'Fail'
        ok, note = await attempt_pipeline(inst['manifest'], shares, ipfs, inst['aad'])
        actual = 'Success' if ok else 'Fail'
        record('shard_granularity_3nodes', f'node_{down_node}_down', rep, expected, actual, f'{len(idxs)}/{N} centres available (node {down_node} of 3 down); {note}')


async def scenario_shard_granularity_10nodes():
    print('[4] Shard availability under N IPFS nodes down (10-node, 1-shard-per-node deployment)')
    for down_count in (0, 1, 2, 3):
        for rep in range(1, 4):
            ipfs = get_backend(10)
            inst = await build_instance(ipfs, PUZZLE_BYTES, LOCKED_BYTES, isolate_control=True)
            ipfs.set_down(set(random.sample(range(10), down_count)))
            idxs, shares = await gather_available(inst, N)
            expected = 'Success' if len(idxs) >= K else 'Fail'
            ok, note = await attempt_pipeline(inst['manifest'], shares, ipfs, inst['aad'])
            actual = 'Success' if ok else 'Fail'
            record('shard_granularity_10nodes', f'{down_count}_nodes_down', rep, expected, actual, f'{len(idxs)}/{N} centres available (down={sorted(ipfs.down_nodes)}); {note}')


async def scenario_wrong_share():
    print('[5] One of the k submitted shares is wrong (bit-flipped, not missing)')
    for rep in range(1, 6):
        ipfs = get_backend(3)
        inst = await build_instance(ipfs, PUZZLE_BYTES, LOCKED_BYTES)
        idxs, shares = await gather_available(inst, N)
        assert len(idxs) == N
        chosen = shares[:K]
        victim = random.randrange(K)
        x, body = chosen[victim][:1], bytearray(chosen[victim][1:])
        body[0] ^= 0xFF
        chosen[victim] = x + bytes(body)
        ok, note = await attempt_pipeline(inst['manifest'], chosen, ipfs, inst['aad'])
        actual = 'Success' if ok else 'Fail'
        record('wrong_share', 'single_share_corrupted', rep, 'Fail', actual, f"Shamir itself can't detect a wrong share (by design, see shamir.py) — the outer AES-GCM tag is what catches it: {note}")


async def scenario_duplicate_share(tmp_root: Path):
    print('[6] Two share files claim the same centre index (coordinator-level)')
    for rep in range(1, 4):
        ipfs = get_backend(3)
        inst = await build_instance(ipfs, PUZZLE_BYTES, LOCKED_BYTES)
        idxs, shares = await gather_available(inst, N)
        share_indices = [0, 1, 2, 3, 4, 5, 6, 0]  # index 0 submitted twice, only 7 distinct centres
        tmp = tmp_root / f'dup_{rep}'
        tmp.mkdir()
        paths = []
        for j, idx in enumerate(share_indices):
            p = tmp / f'share_{j}.json'
            p.write_text(json.dumps({
                'manifest_cid': inst['manifest_cid'],
                'center_id': inst['registry'][idx].id,
                'center_index': idx,
                'share_hex': shares[idx].hex(),
            }))
            paths.append(str(p))
        try:
            await coordinate(inst['manifest_cid'], paths, '/usr/bin/false', ipfs, skip_drand_check=True,)
            actual = 'Success'
            note = 'unexpectedly succeeded'
        except ReconstructError as e:
            actual = 'Fail'
            note = str(e)
        record('duplicate_share', 'same_index_twice', rep, 'Fail', actual, note)


async def scenario_wrong_id_ipfs_swap():
    print('[7] A shard on IPFS claims the wrong centre_id (belt-and-braces IPFS-level check)')
    for rep in range(1, 6):
        ipfs = get_backend(3)
        inst = await build_instance(ipfs, PUZZLE_BYTES, LOCKED_BYTES)
        manifest = await ipfs.cat_json(inst['manifest_cid'])
        victim = random.randrange(N)
        cid = manifest['shard_cids'][victim]['cid']
        node_idx = manifest['shard_cids'][victim]['node_index']
        shard_obj = await ipfs.cat_json(cid, node_index=node_idx)
        wrong_source = (victim + 1) % N
        shard_obj['center_id'] = inst['registry'][wrong_source].id
        ipfs.override(cid, node_idx, json.dumps(shard_obj, sort_keys=True, separators=(",", ":")).encode())
        _, sk_hex = inst['keypairs'][victim]
        try:
            await fetch_and_decrypt_one_shard(manifest, victim, sk_hex, ipfs)
            actual = 'Success'
            note = 'unexpectedly succeeded'
        except ReconstructError as e:
            actual = 'Fail'
            note = str(e)
        record('wrong_centre_id', 'ipfs_shard_swap', rep, 'Fail', actual, note)


async def scenario_wrong_id_coordinator(tmp_root: Path):
    print('\n[8] A share file is mislabeled with the wrong centre_id (coordinator-level check)')
    for rep in range(1, 4):
        ipfs = get_backend(3)
        inst = await build_instance(ipfs, PUZZLE_BYTES, LOCKED_BYTES)
        idxs, shares = await gather_available(inst, N)
        tmp = tmp_root / f'wrongid_{rep}'
        tmp.mkdir()
        paths = []
        for idx in range(K):
            claimed_id = inst['registry'][idx].id
            if idx == K - 1:
                claimed_id = inst['registry'][(idx + 1) % N].id
            p = tmp / f'share_{idx}.json'
            p.write_text(json.dumps({
                'manifest_cid': inst['manifest_cid'],
                'center_id': claimed_id,
                'center_index': idx,
                'share_hex': shares[idx].hex(),
            }))
            paths.append(str(p))
        try:
            await coordinate(inst['manifest_cid'], paths, '/usr/bin/false', ipfs, skip_drand_check=True)
            actual = 'Success'
            note = 'unexpectedly succeeded'
        except ReconstructError as e:
            actual = 'Fail'
            note = str(e)
        record('wrong_centre_id', 'coordinator_mislabeled_file', rep, 'Fail', actual, note)


async def scenario_corrupted_shard_ciphertext():
    print("[9] A shard's ciphertext is bit-flipped on IPFS before the centre decrypts it")
    for rep in range(1, 6):
        ipfs = get_backend(3)
        inst = await build_instance(ipfs, PUZZLE_BYTES, LOCKED_BYTES)
        manifest = await ipfs.cat_json(inst['manifest_cid'])
        victim = random.randrange(N)
        cid = manifest['shard_cids'][victim]['cid']
        node_idx = manifest['shard_cids'][victim]['node_index']
        shard_obj = await ipfs.cat_json(cid, node_index=node_idx)
        ct = bytearray.fromhex(shard_obj['ciphertext_hex'])
        ct[0] ^= 0x01
        shard_obj['ciphertext_hex'] = ct.hex()
        ipfs.override(cid, node_idx, json.dumps(shard_obj, sort_keys=True, separators=(",", ":")).encode())
        _, sk_hex = inst['keypairs'][victim]
        try:
            await fetch_and_decrypt_one_shard(manifest, victim, sk_hex, ipfs)
            actual = 'Success'
            note = 'unexpectedly succeeded'
        except ReconstructError as exc:
            actual = 'Fail'
            note = str(exc)
        record('corrupted_ciphertext', 'shard_layer', rep, 'Fail', actual, note)


async def scenario_corrupted_payload_ciphertext():
    print('[10] The double-locked payload itself is bit-flipped on IPFS')
    for rep in range(1, 6):
        ipfs = get_backend(3)
        inst = await build_instance(ipfs, PUZZLE_BYTES, LOCKED_BYTES)
        manifest = await ipfs.cat_json(inst['manifest_cid'])
        payload = bytearray(await ipfs.cat(manifest['payload_cid'], node_index=0))
        payload[0] ^= 0x01
        ipfs.override(manifest['payload_cid'], 0, bytes(payload))
        idxs, shares = await gather_available(inst, N)
        ok, note = await attempt_pipeline(manifest, shares[:K], ipfs, inst['aad'])
        actual = 'Success' if ok else 'Fail'
        record('corrupted_ciphertext', 'outer_payload_layer', rep, 'Fail', actual, note)


def _round_payload(round_num: int, *, signature: str = 'aa' * 48, randomness: str = 'ee' * 32):
    return {'round': round_num, 'signature': signature, 'randomness': randomness}


def _mock_handler(per_relay_response: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        resp = per_relay_response.get(request.url.host)
        if isinstance(resp, Exception): raise resp
        if isinstance(resp, int): return httpx.Response(status_code=resp)
        return httpx.Response(status_code=200, json=resp)
    return handler


async def _fetch_round_with_mock(per_relay_response: dict, *, min_agreement: int, round_num: int):
    transport = httpx.MockTransport(_mock_handler(per_relay_response))
    with common.patched_httpx_transport(transport):
        return await fetch_round(round_num, min_agreement=min_agreement)


async def _fetch_round_live(down_hosts: set, fake_hosts: dict, *, min_agreement: int, round_num: int):
    transport = common.relay_transport(down_hosts=down_hosts, fake_hosts=fake_hosts)
    with common.patched_httpx_transport(transport):
        return await fetch_round(round_num, min_agreement=min_agreement)


async def _fetch(down_hosts: set, up_hosts: list, fake_hosts: dict, *, threshold: int, round_num: int):
    if DRAND_MODE == 'live':
        return await _fetch_round_live(down_hosts, fake_hosts, min_agreement=threshold, round_num=round_num)
    per_host = {h: httpx.ConnectError('down') for h in down_hosts}
    per_host.update({h: _round_payload(round_num) for h in up_hosts})
    per_host.update(fake_hosts)
    return await _fetch_round_with_mock(per_host, min_agreement=threshold, round_num=round_num)


async def scenario_drand_relays_down() -> None:
    print(f'\n[11] drand relay availability (real fetch_round, {DRAND_MODE} relays)')
    relays = settings.drand_relay_list
    hosts = [httpx.URL(r).host for r in relays]
    threshold = settings.drand_agreement_threshold
    round_num = common.latest_round() - 2 if DRAND_MODE == 'live' else TARGET_ROUND
    for down_count in range(0, len(hosts) + 1):
        for rep in range(1, 4):
            down_hosts = set(random.sample(hosts, down_count))
            up_hosts = [h for h in hosts if h not in down_hosts]
            expected = 'Success' if len(up_hosts) >= threshold else 'Fail'
            t0 = time.perf_counter()
            try:
                info = await _fetch(down_hosts, up_hosts, {}, threshold=threshold, round_num=round_num)
                actual, detail = 'Success', f'randomness {info.randomness[:12]}…'
            except DrandError as exc:
                actual, detail = 'Fail', " | ".join(str(exc).split("\n"))[:300]
            note = (f'{len(up_hosts)}/{len(hosts)} relays reachable, need \u2265{threshold} to agree; '
                    f'round {round_num}; {time.perf_counter() - t0:.3f}s; {detail}')
            record('drand_relay_availability', f'{down_count}_of_{len(hosts)}_relays_down', rep, expected, actual, note,)
    for rep in range(1, 4):
        bad = _round_payload(round_num, signature='bb' * 48, randomness='ff' * 32)
        fake = {hosts[-1]: bad}
        try:
            await _fetch(set(), hosts[:-1], fake, threshold=threshold, round_num=round_num)
            actual = 'Success'
        except DrandError: actual = 'Fail'
        record('drand_relay_availability', 'one_relay_disagrees', rep, 'Success', actual, f'{len(hosts) - 1}/{len(hosts)} relays agree on the real signature, 1 returns a different one — majority should still win (round {round_num})')


async def scenario_drand_gate() -> None:
    print(f'\n[12] drand gate verify_round_published ({DRAND_MODE} relays)')
    latest = common.latest_round()
    hosts = [httpx.URL(r).host for r in settings.drand_relay_list]
    cases = (('published_round', latest - 2, 'Success'), ('future_round', latest + 10, 'Fail'))
    for case, round_num, expected in cases:
        for rep in range(1, 4):
            if DRAND_MODE == 'live':
                transport = common.relay_transport()
            else:
                transport = httpx.MockTransport(_mock_handler({h: _round_payload(round_num) for h in hosts}))
            t0 = time.perf_counter()
            with common.patched_httpx_transport(transport):
                try:
                    await verify_round_published(round_num)
                    actual, detail = 'Success', 'round verified by relay agreement'
                except DrandError as exc:
                    actual, detail = 'Fail', " | ".join(str(exc).split("\n"))[:300]
            record('drand_gate', case, rep, expected, actual, f'round {round_num}; {time.perf_counter() - t0:.3f}s; {detail}')


async def main() -> None:
    global PUZZLE_BYTES, LOCKED_BYTES, DRAND_MODE
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common.add_ipfs_arguments(ap)
    ap.add_argument('--drand', choices=['mock', 'live'], default='mock')
    ap.add_argument('--out', type=Path, default=None)
    args = ap.parse_args()
    DRAND_MODE = args.drand
    out_file = args.out or (RESULTS_FILE if args.ipfs == 'sim' and args.drand == 'mock'
                            else SCRIPT_DIR / f'raw_results_{args.ipfs}_{args.drand}.csv')

    BACKENDS['3'] = await common.make_backend(args, node_count=3)
    BACKENDS['10'] = await common.make_backend(args, node_count=10, need_control=True)
    RUN_INFO.update({'ipfs_backend': BACKENDS['3'].name, 'outage_mode': BACKENDS['3'].outage_mode,
                     'drand_backend': DRAND_MODE})

    print('Starting Experiment 07: Failure Testing')
    print(f'Storage: {BACKENDS["3"].describe()} / {BACKENDS["10"].describe()}; drand: {DRAND_MODE}')
    if VAJRA_BIN is not None: print(f'Found compiled vajra binary at {VAJRA_BIN} — success-path cases will run real `vajra solve`.')
    else: print('No compiled vajra binary found at rust/target/release/. This script does NOT build one (no server/toolchain assumed) — success-path cases will stop one step short of `vajra solve` instead (data_key + outer AES-GCM verified correct). Run `make rs-build` first for the full end-to-end check.')

    with TemporaryDirectory(prefix="vajra_exp07_") as tmp:
        tmp_path = Path(tmp)
        if VAJRA_BIN is not None:
            PUZZLE_BYTES, LOCKED_BYTES = prepare_real_puzzle(VAJRA_BIN, tmp_path)
        else:
            PUZZLE_BYTES = b'{"stub": "no compiled vajra binary available"}'
            LOCKED_BYTES = b'{"stub": "stand-in inner locked.json - no vajra solve step run"}'

        try:
            await scenario_manifest_control_spof()
            await scenario_shard_granularity_3nodes()
            await scenario_shard_granularity_10nodes()
            await scenario_wrong_share()
            await scenario_duplicate_share(tmp_path)
            await scenario_wrong_id_ipfs_swap()
            await scenario_wrong_id_coordinator(tmp_path)
            await scenario_corrupted_shard_ciphertext()
            await scenario_corrupted_payload_ciphertext()
            await scenario_drand_relays_down()
            if DRAND_MODE == 'live':
                await scenario_drand_gate()
        finally:
            for backend in BACKENDS.values():
                backend.reset()

    with open(out_file, 'w', newline='', encoding='utf-8') as fp:
        writer = csv.DictWriter(fp, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    total = len(results)
    passed = sum(1 for r in results if r['passed'])
    print(f'Experiment complete: {passed}/{total} outcomes matched expectation.')
    print(f'See {out_file}')
    if passed != total:
        print('Mismatches (investigate before trusting the rest):')
        for r in results:
            if not r['passed']:
                print(f"{r['scenario']}/{r['case']} #{r['repetition']}: {r['notes']}")


if __name__ == '__main__':
    asyncio.run(main())
