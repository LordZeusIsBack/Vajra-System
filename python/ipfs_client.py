"""ipfs_client.py — Async wrapper around one or more Kubo HTTP RPC nodes.

MULTI-NODE ROUND-ROBIN
  When multiple IPFS_API_URLS are configured, shards are distributed
  across nodes using shard_index % len(nodes). Each node receives
  roughly n/len(nodes) shards. If a node goes down after upload,
  a center can still reconstruct as long as it can reach enough
  other nodes to collect k valid Shamir shares.

  Passing node_index to add_bytes / add_json selects the node.
  All other operations (cat, pin, version) default to node 0.

Reference: https://docs.ipfs.tech/reference/kubo/rpc/
"""

import json as _json

import httpx

from config import settings


class IPFSError(RuntimeError):
    """Raised when Kubo returns an unexpected response."""


class IPFSClient:
    """Async client for one or more Kubo RPC nodes.

    Instantiate once at app startup; each method opens its own short-lived
    AsyncClient so there is no connection-pool state to manage.

    Args:
        node_urls: List of Kubo API base URLs (e.g. ``["http://127.0.0.1:5001"]``).
                   Falls back to ``settings.ipfs_node_list`` when omitted.
    """

    def __init__(self, node_urls: list[str] | None = None) -> None:
        raw = node_urls or settings.ipfs_node_list
        self._nodes: list[str] = [u.rstrip("/") + "/api/v0" for u in raw]

    # ── Node selection ────────────────────────────────────────────────────────

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    def node_for(self, index: int) -> str:
        """Return the API base URL for round-robin index ``index``."""
        return self._nodes[index % len(self._nodes)]

    # ── Core operations ───────────────────────────────────────────────────────

    async def add_bytes(
        self,
        data: bytes,
        filename: str = "blob",
        *,
        node_index: int = 0,
        pin: bool = True,
        cid_version: int = 1,
    ) -> str:
        """Add raw bytes to the node selected by ``node_index``. Returns CIDv1.

        Args:
            data:        Payload to upload.
            filename:    Filename hint in the multipart form (cosmetic only).
            node_index:  Selects ``nodes[node_index % len(nodes)]``.
            pin:         Pin the content on the receiving node immediately.
            cid_version: 0 = CIDv0 (Qm…), 1 = CIDv1 (bafy…, default).
        """
        node = self.node_for(node_index)
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{node}/add",
                params={"pin": str(pin).lower(), "cid-version": str(cid_version)},
                files={"file": (filename, data, "application/octet-stream")},
            )
        self._raise_for_status(resp)
        return resp.json()["Hash"]

    async def add_json(
        self,
        obj: dict,
        filename: str = "data.json",
        *,
        node_index: int = 0,
        pin: bool = True,
        cid_version: int = 1,
    ) -> str:
        """Serialise *obj* to compact sorted JSON, add to IPFS. Returns CID."""
        payload = _json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
        return await self.add_bytes(
            payload, filename,
            node_index=node_index, pin=pin, cid_version=cid_version,
        )

    async def cat(self, cid: str, *, node_index: int = 0) -> bytes:
        """Fetch raw bytes for *cid* from the selected node."""
        node = self.node_for(node_index)
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(f"{node}/cat", params={"arg": cid})
        self._raise_for_status(resp)
        return resp.content

    async def cat_json(self, cid: str, *, node_index: int = 0) -> dict:
        """Fetch and JSON-parse the content at *cid*."""
        raw = await self.cat(cid, node_index=node_index)
        try:
            return _json.loads(raw)
        except _json.JSONDecodeError as exc:
            raise IPFSError(f"CID {cid!r} does not contain valid JSON") from exc

    async def pin(self, cid: str, *, node_index: int = 0) -> None:
        """Explicitly pin a CID (``add_bytes`` already pins; use for re-pinning)."""
        node = self.node_for(node_index)
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{node}/pin/add", params={"arg": cid})
        self._raise_for_status(resp)

    async def version(self, *, node_index: int = 0) -> str:
        """Return the Kubo version string from the selected node."""
        node = self.node_for(node_index)
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(f"{node}/version")
        self._raise_for_status(resp)
        return resp.json().get("Version", "unknown")

    # ── Health check (all nodes) ──────────────────────────────────────────────

    async def health_check_all(self) -> dict[str, str | None]:
        """Probe every configured node. Returns {url: version_or_None}."""
        results: dict[str, str | None] = {}
        for i, node in enumerate(self._nodes):
            try:
                ver = await self.version(node_index=i)
                results[node] = ver
            except Exception:
                results[node] = None
        return results

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        if resp.is_success:
            return
        try:
            detail = resp.json().get("Message", resp.text[:300])
        except Exception:
            detail = resp.text[:300]
        raise IPFSError(f"Kubo {resp.status_code}: {detail}")
