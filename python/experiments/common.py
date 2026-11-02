from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx

EXPERIMENTS_DIR = Path(__file__).resolve().parent
PYTHON_DIR = EXPERIMENTS_DIR.parent
REPO_ROOT = PYTHON_DIR.parent
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))
if str(EXPERIMENTS_DIR) not in sys.path:
    sys.path.insert(0, str(EXPERIMENTS_DIR))

os.environ.setdefault("MANIFEST_HMAC_SECRET", secrets.token_hex(32))

from ipfs_client import IPFSClient, IPFSError


def find_vajra_binary(required: bool = True) -> Path | None:
    exe = "vajra.exe" if platform.system() == "Windows" else "vajra"
    candidate = REPO_ROOT / "rust" / "target" / "release" / exe
    if candidate.exists():
        return candidate
    if required:
        raise SystemExit(
            f"Compiled vajra binary not found at {candidate}\n"
            "Build it first:  make rs-build   (or: cd rust && cargo build --release)"
        )
    return None


def _canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()


class SimulatedIPFS:

    is_real = False
    name = "simulated"
    outage_mode = "simulated"

    def __init__(self, node_count: int = 3) -> None:
        self.node_count = node_count
        self._nodes: list[dict[str, bytes]] = [{} for _ in range(node_count)]
        self._control: dict[str, bytes] = {}
        self._overrides: dict[tuple[str, int], bytes] = {}
        self.down_nodes: set[int] = set()

    async def add_bytes(self, data: bytes, filename: str = "blob", *,
                        node_index: int = 0, control: bool = False) -> str:
        cid = "sim-" + hashlib.sha256(data).hexdigest()[:46]
        if control:
            self._control[cid] = data
        else:
            self._nodes[node_index % self.node_count][cid] = data
        return cid

    async def add_json(self, obj: dict, filename: str = "data.json", *,
                       node_index: int = 0, control: bool = False) -> str:
        return await self.add_bytes(_canonical_json(obj), filename,
                                    node_index=node_index, control=control)

    async def cat(self, cid: str, *, node_index: int = 0) -> bytes:
        if cid in self._control:
            return self._control[cid]
        node = node_index % self.node_count
        if node in self.down_nodes:
            raise IPFSError(f"simulated node {node} is down")
        if (cid, node) in self._overrides:
            return self._overrides[(cid, node)]
        if cid not in self._nodes[node]:
            raise IPFSError(f"CID {cid} not present on simulated node {node}")
        return self._nodes[node][cid]

    async def cat_json(self, cid: str, *, node_index: int = 0) -> dict:
        try:
            return json.loads(await self.cat(cid, node_index=node_index))
        except json.JSONDecodeError as exc:
            raise IPFSError(f"CID {cid} is not JSON") from exc

    def override(self, cid: str, node_index: int, data: bytes) -> None:
        self._overrides[(cid, node_index % self.node_count)] = data

    def set_down(self, nodes: set[int]) -> None:
        self.down_nodes = set(nodes)

    def reset(self) -> None:
        self._overrides.clear()
        self.set_down(set())

    def describe(self) -> dict:
        return {"ipfs_backend": self.name, "ipfs_nodes": self.node_count,
                "outage_mode": self.outage_mode}


class RealIPFS:
    is_real = True
    name = "real"

    def __init__(self, urls: list[str], *, node_count: int | None = None,
                 control_url: str | None = None, outage_mode: str = "client",
                 cluster_dir: Path | None = None) -> None:
        if outage_mode not in ("client", "process"):
            raise ValueError("outage_mode must be 'client' or 'process'")
        self.urls = [u.rstrip("/") for u in urls]
        self.node_count = node_count or len(self.urls)
        if self.node_count > len(self.urls):
            raise ValueError(f"need {self.node_count} Kubo URLs, got {len(self.urls)}")
        self._client = IPFSClient(self.urls[: self.node_count])
        self._control_client = IPFSClient([control_url]) if control_url else None
        self._control_cids: set[str] = set()
        self._overrides: dict[tuple[str, int], bytes] = {}
        self.down_nodes: set[int] = set()
        self.outage_mode = outage_mode
        self.cluster_dir = cluster_dir
        self.versions: dict[str, str | None] = {}

    async def probe(self) -> None:
        urls = self.urls[: self.node_count]
        for i, url in enumerate(urls):
            self.versions[url] = await self._client.version(node_index=i)
        if self._control_client is not None:
            self.versions["control"] = await self._control_client.version()

    async def add_bytes(self, data: bytes, filename: str = "blob", *,
                        node_index: int = 0, control: bool = False) -> str:
        if control:
            if self._control_client is None:
                raise IPFSError("no control node configured (pass one more Kubo URL)")
            cid = await self._control_client.add_bytes(data, filename)
            self._control_cids.add(cid)
            return cid
        return await self._client.add_bytes(data, filename, node_index=node_index % self.node_count)

    async def add_json(self, obj: dict, filename: str = "data.json", *,
                       node_index: int = 0, control: bool = False) -> str:
        return await self.add_bytes(_canonical_json(obj), filename,
                                    node_index=node_index, control=control)

    async def cat(self, cid: str, *, node_index: int = 0) -> bytes:
        if cid in self._control_cids and self._control_client is not None:
            return await self._control_client.cat(cid)
        node = node_index % self.node_count
        if node in self.down_nodes and self.outage_mode == "client":
            raise IPFSError(f"node {node} marked down (client-side outage)")
        if (cid, node) in self._overrides:
            await self._client.cat(cid, node_index=node)
            return self._overrides[(cid, node)]
        try:
            return await self._client.cat(cid, node_index=node)
        except httpx.HTTPError as exc:
            raise IPFSError(f"node {node} unreachable: {exc.__class__.__name__}") from exc

    async def cat_json(self, cid: str, *, node_index: int = 0) -> dict:
        try:
            return json.loads(await self.cat(cid, node_index=node_index))
        except json.JSONDecodeError as exc:
            raise IPFSError(f"CID {cid} is not JSON") from exc

    def override(self, cid: str, node_index: int, data: bytes) -> None:
        self._overrides[(cid, node_index % self.node_count)] = data

    def set_down(self, nodes: set[int]) -> None:
        nodes = set(nodes)
        if self.outage_mode == "process":
            import kubo_cluster
            base = self.cluster_dir or kubo_cluster.DEFAULT_DIR
            for i in sorted(self.down_nodes - nodes):
                kubo_cluster.start(base, node=i)
            for i in sorted(nodes - self.down_nodes):
                kubo_cluster.stop(base, node=i)
        self.down_nodes = nodes

    def reset(self) -> None:
        self._overrides.clear()
        self.set_down(set())

    def describe(self) -> dict:
        return {"ipfs_backend": self.name, "ipfs_nodes": self.node_count,
                "outage_mode": self.outage_mode}


def add_ipfs_arguments(parser, *, default: str = "sim", allow_auto: bool = False) -> None:
    """Add the --ipfs / --ipfs-urls / --outage options used by the experiments."""
    choices = ["auto", "sim", "real"] if allow_auto else ["sim", "real"]
    parser.add_argument("--ipfs", choices=choices, default=default,
                        help="storage backend: in-memory simulation or real Kubo nodes"
                             + (" (auto: real if reachable)" if allow_auto else ""))
    parser.add_argument("--ipfs-urls", default=os.environ.get("IPFS_API_URLS", ""),
                        help="comma-separated Kubo RPC URLs (default: $IPFS_API_URLS, "
                             "or the cluster started by kubo_cluster.py)")
    parser.add_argument("--outage", choices=["client", "process"], default="client",
                        help="how --ipfs real makes a node unavailable (see common.py)")
    parser.add_argument("--cluster-dir", type=Path, default=None,
                        help="kubo_cluster.py directory (for --outage process)")


def resolve_ipfs_urls(args) -> list[str]:
    urls = [u.strip() for u in (args.ipfs_urls or "").split(",") if u.strip()]
    if urls:
        return urls
    import kubo_cluster
    return kubo_cluster.node_urls(args.cluster_dir or kubo_cluster.DEFAULT_DIR)


async def make_backend(args, *, node_count: int, need_control: bool = False):
    if args.ipfs == "sim":
        return SimulatedIPFS(node_count=node_count)
    urls = resolve_ipfs_urls(args)
    needed = node_count + (1 if need_control else 0)
    if len(urls) < needed:
        raise SystemExit(f"--ipfs real needs {needed} Kubo URLs here, got {len(urls)}")
    backend = RealIPFS(urls, node_count=node_count,
                       control_url=urls[node_count] if need_control else None,
                       outage_mode=args.outage, cluster_dir=args.cluster_dir)
    await backend.probe()
    return backend


def latest_round(now: float | None = None) -> int:
    from config import settings
    now = time.time() if now is None else now
    return int((now - settings.drand_genesis) // settings.drand_period) + 1


def relay_transport(*, down_hosts: set[str] = frozenset(),
                    fake_hosts: dict[str, dict] | None = None) -> httpx.AsyncBaseTransport:
    real = httpx.AsyncHTTPTransport(retries=0)
    fake_hosts = fake_hosts or {}

    class _Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            host = request.url.host
            if host in down_hosts:
                raise httpx.ConnectError("relay marked down by the experiment", request=request)
            if host in fake_hosts:
                return httpx.Response(200, json=fake_hosts[host], request=request)
            return await real.handle_async_request(request)

        async def aclose(self) -> None:
            await real.aclose()

    return _Transport()


class patched_httpx_transport:
    def __init__(self, transport: httpx.AsyncBaseTransport, hosts: set[str] | None = None) -> None:
        from config import settings
        self.transport = transport
        self.hosts = hosts if hosts is not None else {
            httpx.URL(r).host for r in settings.drand_relay_list
        }
        self._original = httpx.AsyncClient

    def __enter__(self):
        original, inner, hosts = self._original, self.transport, self.hosts

        class _Router(httpx.AsyncBaseTransport):
            def __init__(self, default: httpx.AsyncBaseTransport) -> None:
                self.default = default

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                if request.url.host in hosts:
                    return await inner.handle_async_request(request)
                return await self.default.handle_async_request(request)

            async def aclose(self) -> None:
                await self.default.aclose()

        def factory(*args, **kwargs):
            default = kwargs.pop("transport", None) or httpx.AsyncHTTPTransport()
            kwargs["transport"] = _Router(default)
            return original(*args, **kwargs)

        httpx.AsyncClient = factory
        return self

    def __exit__(self, *exc) -> None:
        httpx.AsyncClient = self._original


def _cmd(args: list[str], timeout: float = 5.0) -> str:
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                             encoding="utf-8", errors="replace")
        return out.stdout.strip()
    except Exception:
        return ""


def _read(path: str) -> str:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return ""


def cpu_model_name() -> str:
    system = platform.system()
    if system == "Windows":
        name = _cmd(["powershell", "-NoProfile", "-Command",
                     "(Get-CimInstance Win32_Processor | Select-Object -First 1).Name"])
        if not name and shutil.which("wmic"):
            lines = [ln.strip() for ln in _cmd(["wmic", "cpu", "get", "name"]).splitlines()]
            name = next((ln for ln in lines[1:] if ln), "")
        return name
    if system == "Darwin":
        return _cmd(["sysctl", "-n", "machdep.cpu.brand_string"]) or _cmd(
            ["sysctl", "-n", "hw.model"])
    if system == "Linux":
        for line in _read("/proc/cpuinfo").splitlines():
            if line.lower().startswith(("model name", "hardware")):
                return line.split(":", 1)[1].strip()
        lscpu = _cmd(["lscpu"])
        m = re.search(r"Model name:\s*(.+)", lscpu)
        return m.group(1).strip() if m else ""
    return ""


def power_settings() -> dict[str, str]:
    out: dict[str, str] = {}
    system = platform.system()
    if system == "Windows":
        out["power_plan"] = _cmd(["powercfg", "/getactivescheme"])
    elif system == "Linux":
        out["cpufreq_governor"] = _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        out["cpufreq_driver"] = _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver")
        out["energy_perf_preference"] = _read(
            "/sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference")
        boost = _read("/sys/devices/system/cpu/cpufreq/boost") or _read(
            "/sys/devices/system/cpu/intel_pstate/no_turbo")
        out["turbo_setting"] = boost
    elif system == "Darwin":
        out["power_settings"] = " ".join(_cmd(["pmset", "-g"]).split())
    try:
        import psutil
        battery = psutil.sensors_battery()
        out["on_ac_power"] = "" if battery is None else str(bool(battery.power_plugged))
    except Exception:
        out["on_ac_power"] = ""
    return out


def ec2_instance_type(timeout: float = 1.0) -> str:
    vendor = _read("/sys/devices/virtual/dmi/id/sys_vendor") + _read("/sys/hypervisor/uuid")
    if platform.system() == "Linux" and "amazon" not in vendor.lower() and not vendor.startswith("ec2"):
        return ""
    try:
        token = httpx.put("http://169.254.169.254/latest/api/token",
                          headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
                          timeout=timeout).text
        return httpx.get("http://169.254.169.254/latest/meta-data/instance-type",
                         headers={"X-aws-ec2-metadata-token": token}, timeout=timeout).text.strip()
    except Exception:
        return ""


def host_info() -> dict[str, Any]:
    import psutil
    try:
        rustc = _cmd(["rustc", "--version"])
    except Exception:
        rustc = ""
    freq = psutil.cpu_freq()
    info: dict[str, Any] = {
        "Machine": platform.node(),
        "OS": f"{platform.system()} {platform.release()}",
        "OS_version": platform.version(),
        "Arch": platform.machine(),
        "CPU": platform.processor(),
        "CPU_model": cpu_model_name(),
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "cpu_max_mhz": round(freq.max, 1) if freq and freq.max else "",
        "RAM_GB": round(psutil.virtual_memory().total / (1024 ** 3), 2),
        "Rust Version": rustc,
        "Python": platform.python_version(),
        "ec2_instance_type": ec2_instance_type(),
    }
    info.update(power_settings())
    return info


def runtime_state() -> dict[str, Any]:
    import psutil
    state: dict[str, Any] = {}
    freq = psutil.cpu_freq()
    state["cpu_mhz_now"] = round(freq.current, 1) if freq else ""
    state["cpu_percent_1s"] = psutil.cpu_percent(interval=1.0)
    try:
        state["load_avg_1m"] = round(os.getloadavg()[0], 2)
    except (AttributeError, OSError):
        state["load_avg_1m"] = ""
    temps = getattr(psutil, "sensors_temperatures", None)
    try:
        readings = temps() if temps else {}
        values = [t.current for group in readings.values() for t in group if t.current]
        state["max_temp_c"] = round(max(values), 1) if values else ""
    except Exception:
        state["max_temp_c"] = ""
    return state
