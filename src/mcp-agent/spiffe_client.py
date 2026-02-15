"""
SPIFFE Client for MCP Agent
Handles JWT-SVID fetching and automatic rotation via py-spiffe.
Fail-closed: requires a running SPIRE agent. No fallback.
"""
import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

TRUST_DOMAIN = "mcp-identity.local"


@dataclass
class SVID:
    """SPIFFE Verifiable Identity Document"""
    spiffe_id: str
    token: str
    expiry: datetime
    hint: str = ""
    is_real: bool = False


class SpiffeClient:
    """
    SPIFFE Workload API client.
    Connects to SPIRE agent via py-spiffe for real JWT-SVIDs.
    Fail-closed: if SPIRE is unavailable, no SVID is issued.
    """

    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self._current_svid: Optional[SVID] = None
        self._watch_task: Optional[asyncio.Task] = None
        self._running = False
        self._workload_client = None
        self._connected = False

    async def start(self):
        """Start SVID watcher and connect to SPIRE agent"""
        self._running = True

        from spiffe import WorkloadApiClient
        socket = self.socket_path
        if socket.startswith("unix://"):
            socket = socket[len("unix://"):]
        self._workload_client = WorkloadApiClient(
            socket_path=f"unix://{socket}"
        )
        # Verify SPIRE connection — fail loudly if unavailable
        try:
            loop = asyncio.get_event_loop()
            jwt_svid = await loop.run_in_executor(
                None,
                lambda: self._workload_client.fetch_jwt_svid(
                    audience={"mcp-identity"}
                )
            )
            if jwt_svid:
                self._connected = True
                logger.info("Connected to SPIRE agent")
        except Exception as e:
            logger.error(f"SPIRE agent not available — agent will not have identity: {e}")
            self._connected = False

        self._watch_task = asyncio.create_task(self._watch_svids())
        logger.info(f"SPIFFE client started (connected={self._connected})")

    async def stop(self):
        """Stop SVID watcher"""
        self._running = False
        if self._watch_task:
            self._watch_task.cancel()
            try:
                await self._watch_task
            except asyncio.CancelledError:
                pass
        if self._workload_client:
            try:
                self._workload_client.close()
            except Exception:
                pass
        logger.info("SPIFFE client stopped")

    async def _watch_svids(self):
        """Watch for SVID updates"""
        while self._running:
            try:
                svid = await self._fetch_svid()
                if svid:
                    self._current_svid = svid
                    logger.info(
                        f"SVID updated: {svid.spiffe_id} "
                        f"(real={svid.is_real}, expires={svid.expiry.isoformat()})"
                    )
            except Exception as e:
                logger.error(f"Error fetching SVID: {e}")
            await asyncio.sleep(60)

    async def _fetch_svid(self) -> Optional[SVID]:
        """Fetch JWT-SVID from SPIRE. Returns None if SPIRE is unavailable (fail-closed)."""
        if not self._connected or not self._workload_client:
            return None
        try:
            loop = asyncio.get_event_loop()
            jwt_svid = await loop.run_in_executor(
                None,
                lambda: self._workload_client.fetch_jwt_svid(
                    audience={"mcp-identity"}
                )
            )
            # expiry is a Unix timestamp (int) in py-spiffe
            expiry = datetime.fromtimestamp(jwt_svid.expiry, tz=timezone.utc) \
                if isinstance(jwt_svid.expiry, (int, float)) \
                else datetime.now(timezone.utc) + timedelta(minutes=5)
            return SVID(
                spiffe_id=str(jwt_svid.spiffe_id),
                token=jwt_svid.token,
                expiry=expiry,
                hint="",
                is_real=True
            )
        except Exception as e:
            logger.error(f"SVID fetch failed (no fallback): {e}")
            return None

    async def get_svid(self) -> Optional[SVID]:
        """Get current SVID, refreshing if expired"""
        if self._current_svid:
            now = datetime.now(timezone.utc)
            expiry = self._current_svid.expiry
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry > now:
                return self._current_svid
        self._current_svid = await self._fetch_svid()
        return self._current_svid

    async def get_jwt_token(self, audience: str = "mcp-identity") -> Optional[str]:
        """Get JWT token for specific audience"""
        svid = await self.get_svid()
        return svid.token if svid else None

    @property
    def is_real_mode(self) -> bool:
        """Whether client is connected to SPIRE agent"""
        return self._connected
