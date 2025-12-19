from __future__ import annotations

import os
import asyncio
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@dataclass(frozen=True)
class MCPServerConfig:
    command: str
    args: List[str]

    @staticmethod
    def default() -> "MCPServerConfig":
        command = os.getenv("MITRE_MCP_COMMAND", "npx")
        args_raw = os.getenv("MITRE_MCP_ARGS", "-y @imouiche/mitre-attack-mcp-server")
        return MCPServerConfig(command=command, args=args_raw.split())


class MitreMcpClient:
    """
    MCP stdio client that reuses a single server session.
    Safe for concurrent tool calls and clean shutdown.
    """

    def __init__(self, config: Optional[MCPServerConfig] = None) -> None:
        self.config = config or MCPServerConfig.default()

        self._ctx = None
        self._read = None
        self._write = None
        self._session: Optional[ClientSession] = None

        # Concurrency / lifecycle controls
        self._connect_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()
        self._closing = False

        self._inflight = 0
        self._no_inflight = asyncio.Event()
        self._no_inflight.set()

    async def __aenter__(self) -> "MitreMcpClient":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def connect(self) -> None:
        # Fast path
        if self._session is not None:
            return

        async with self._connect_lock:
            # Double-check after acquiring lock
            if self._session is not None:
                return
            if self._closing:
                raise RuntimeError("Client is closing; cannot connect.")

            server_params = StdioServerParameters(
                command=self.config.command,
                args=self.config.args,
            )

            # Keep the stdio context open
            self._ctx = stdio_client(server_params)
            self._read, self._write = await self._ctx.__aenter__()

            # Keep the MCP session open
            self._session = ClientSession(self._read, self._write)
            await self._session.__aenter__()
            await self._session.initialize()

    async def close(self) -> None:
        # Ensure close is only running once
        async with self._close_lock:
            if self._closing:
                return
            self._closing = True

            # Wait for any inflight tool calls to finish
            await self._no_inflight.wait()

            # Close MCP session first
            if self._session is not None:
                try:
                    await self._session.__aexit__(None, None, None)
                finally:
                    self._session = None

            # Then close stdio client context
            if self._ctx is not None:
                try:
                    await self._ctx.__aexit__(None, None, None)
                finally:
                    self._ctx = None
                    self._read = None
                    self._write = None

    async def list_tools(self) -> List[Dict[str, Any]]:
        await self.connect()
        assert self._session is not None

        self._begin_call()
        try:
            resp = await self._session.list_tools()
            return [{"name": t.name, "description": t.description, "inputSchema": t.inputSchema} for t in resp.tools]
        finally:
            self._end_call()

    async def call_tool(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        await self.connect()
        assert self._session is not None

        self._begin_call()
        try:
            result = await self._session.call_tool(tool_name, arguments or {})
            if hasattr(result, "structuredContent") and result.structuredContent is not None:
                return result.structuredContent
            if hasattr(result, "content"):
                return result.content
            return result
        finally:
            self._end_call()

    def _begin_call(self) -> None:
        # Called from within the event loop thread
        if self._closing:
            raise RuntimeError("Client is closing; refusing new requests.")
        self._inflight += 1
        if self._inflight == 1:
            self._no_inflight.clear()

    def _end_call(self) -> None:
        self._inflight -= 1
        if self._inflight <= 0:
            self._inflight = 0
            self._no_inflight.set()
