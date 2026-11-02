from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import httpx

DEFAULT_DIR = Path(__file__).resolve().parent / ".kubo-cluster"


def _meta_path(base: Path) -> Path:
    return base / "cluster.json"


def load_meta(base: Path = DEFAULT_DIR) -> dict:
    p = _meta_path(base)
    if not p.exists():
        raise SystemExit(f"No cluster at {base}. Run: python kubo_cluster.py init --nodes N")
    return json.loads(p.read_text())


def _save_meta(base: Path, meta: dict) -> None:
    _meta_path(base).write_text(json.dumps(meta, indent=2))


def node_urls(base: Path = DEFAULT_DIR) -> list[str]:
    meta = load_meta(base)
    return [f"http://127.0.0.1:{meta['api_port'] + i}" for i in range(meta["nodes"])]


def _ipfs(meta: dict, i: int, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    env = {**os.environ, "IPFS_PATH": str(Path(meta["dir"]) / f"node{i}")}
    return subprocess.run(
        [meta["ipfs_bin"], *args], env=env, capture_output=True, text=True, check=check,
    )


def init(base: Path, nodes: int, api_port: int, ipfs_bin: str) -> None:
    resolved = shutil.which(ipfs_bin) or ipfs_bin
    if not Path(resolved).exists():
        raise SystemExit(
            f"Kubo binary {ipfs_bin!r} not found. Install Kubo "
            "(https://docs.ipfs.tech/install/command-line/) or pass --ipfs-bin."
        )
    base.mkdir(parents=True, exist_ok=True)
    meta = {
        "dir": str(base.resolve()),
        "nodes": nodes,
        "api_port": api_port,
        "ipfs_bin": resolved,
        "version": None,
    }
    meta["version"] = _ipfs(meta, 0, "version", "--number", check=False).stdout.strip()
    for i in range(nodes):
        repo = base / f"node{i}"
        if repo.exists():
            print(f"node{i}: repository exists, keeping it")
            continue
        _ipfs(meta, i, "init", "--profile=test")
        _ipfs(meta, i, "config", "Addresses.API", f"/ip4/127.0.0.1/tcp/{api_port + i}")
        _ipfs(meta, i, "config", "Addresses.Gateway", "/ip4/127.0.0.1/tcp/0")
        _ipfs(meta, i, "config", "--json", "Addresses.Swarm", '["/ip4/127.0.0.1/tcp/0"]')
        print(f"node{i}: initialised (API port {api_port + i})")
    _save_meta(base, meta)
    print(f"Kubo {meta['version']} cluster of {nodes} nodes in {base}")


def _pid_file(meta: dict, i: int) -> Path:
    return Path(meta["dir"]) / f"node{i}.pid"


def _alive(pid: int) -> bool:
    try:
        import psutil
        return psutil.pid_exists(pid) and psutil.Process(pid).status() != "zombie"
    except Exception:
        return False


def _wait_api(url: str, up: bool, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            ok = httpx.post(f"{url}/api/v0/version", timeout=1.0).is_success
        except httpx.HTTPError:
            ok = False
        if ok == up:
            return True
        time.sleep(0.2)
    return False


def start(base: Path, node: int | None = None, peered: bool | None = None) -> None:
    meta = load_meta(base)
    if peered is not None:
        meta["peered"] = peered
        _save_meta(base, meta)
    peered = bool(meta.get("peered", False))
    targets = range(meta["nodes"]) if node is None else [node]
    for i in targets:
        pid_file = _pid_file(meta, i)
        if pid_file.exists() and _alive(int(pid_file.read_text())):
            continue
        env = {**os.environ, "IPFS_PATH": str(Path(meta["dir"]) / f"node{i}")}
        args = [meta["ipfs_bin"], "daemon"] + ([] if peered else ["--offline"])
        log = open(Path(meta["dir"]) / f"node{i}.log", "ab")
        kwargs: dict = {"env": env, "stdout": log, "stderr": subprocess.STDOUT}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        proc = subprocess.Popen(args, **kwargs)
        pid_file.write_text(str(proc.pid))
    urls = [f"http://127.0.0.1:{meta['api_port'] + i}" for i in range(meta["nodes"])]
    for i in targets:
        if not _wait_api(urls[i], up=True):
            raise SystemExit(f"node{i} did not come up; see {meta['dir']}/node{i}.log")
    if peered:
        _connect_all(meta)
    mode = "peered" if peered else "isolated (--offline)"
    print(f"started {len(list(targets))} node(s), {mode}")


def _connect_all(meta: dict) -> None:
    addrs = []
    for i in range(meta["nodes"]):
        info = json.loads(_ipfs(meta, i, "id").stdout)
        tcp = [a for a in info.get("Addresses") or [] if "/tcp/" in a and "127.0.0.1" in a]
        addrs.append(tcp[0] if tcp else None)
    for i in range(meta["nodes"]):
        for j in range(meta["nodes"]):
            if i != j and addrs[j]:
                _ipfs(meta, i, "swarm", "connect", addrs[j], check=False)


def stop(base: Path, node: int | None = None) -> None:
    meta = load_meta(base)
    targets = range(meta["nodes"]) if node is None else [node]
    for i in targets:
        pid_file = _pid_file(meta, i)
        if not pid_file.exists():
            continue
        pid = int(pid_file.read_text())
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=15)
        except Exception:
            pass
        pid_file.unlink(missing_ok=True)
        _wait_api(f"http://127.0.0.1:{meta['api_port'] + i}", up=False, timeout=10)
    print(f"stopped {len(list(targets))} node(s)")


def status(base: Path) -> list[bool]:
    meta = load_meta(base)
    states = []
    for i in range(meta["nodes"]):
        url = f"http://127.0.0.1:{meta['api_port'] + i}"
        try:
            up = httpx.post(f"{url}/api/v0/version", timeout=1.0).is_success
        except httpx.HTTPError:
            up = False
        states.append(up)
        print(f"node{i}  {url}  {'up' if up else 'down'}")
    return states


def destroy(base: Path) -> None:
    if _meta_path(base).exists():
        stop(base)
    shutil.rmtree(base, ignore_errors=True)
    print(f"removed {base}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", choices=["init", "start", "stop", "status", "urls", "destroy"])
    p.add_argument("--dir", type=Path, default=DEFAULT_DIR)
    p.add_argument("--nodes", type=int, default=11, help="init: number of nodes (default 11)")
    p.add_argument("--api-port", type=int, default=5001, help="init: API port of node 0")
    p.add_argument("--ipfs-bin", default="ipfs", help="init: path to the Kubo binary")
    p.add_argument("--node", type=int, default=None, help="start/stop: a single node index")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--peered", action="store_true", help="start: run online and interconnected")
    mode.add_argument("--isolated", action="store_true", help="start: run with --offline (default)")
    a = p.parse_args()
    if a.command == "init":
        init(a.dir, a.nodes, a.api_port, a.ipfs_bin)
    elif a.command == "start":
        start(a.dir, a.node, True if a.peered else (False if a.isolated else None))
    elif a.command == "stop":
        stop(a.dir, a.node)
    elif a.command == "status":
        status(a.dir)
    elif a.command == "urls":
        print(",".join(node_urls(a.dir)))
    elif a.command == "destroy":
        destroy(a.dir)


if __name__ == "__main__":
    main()
