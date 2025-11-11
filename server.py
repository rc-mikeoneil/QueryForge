from __future__ import annotations

import logging
import os
import threading
from pathlib import Path

if __package__ is None or __package__ == "":  # pragma: no cover - direct script execution
    import sys

    sys.path.append(str(Path(__file__).resolve().parent.parent))

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from server_runtime import ServerRuntime
from server_tools_cbc import register_cbc_tools
from server_tools_cbr import register_cbr_tools
from server_tools_cortex import register_cortex_tools
from server_tools_kql import register_kql_tools
from server_tools_s1 import register_s1_tools
from server_tools_shared import register_shared_tools

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

mcp = FastMCP(name="queryforge")
runtime = ServerRuntime()

# Export rag_service for direct access (used in embeddings generation)
rag_service = runtime.rag_service

register_cbc_tools(mcp, runtime)
register_cbr_tools(mcp, runtime)
register_cortex_tools(mcp, runtime)
register_kql_tools(mcp, runtime)
register_s1_tools(mcp, runtime)
register_shared_tools(mcp, runtime)


def main() -> None:
    """Entry point for launching the MCP server."""

    logger.info("🚀 Starting QueryForge MCP server")

    runtime.initialize_critical_components()

    init_thread = threading.Thread(
        target=runtime.initialize_rag_background,
        daemon=True,
        name="RAG-Init",
    )
    init_thread.start()
    logger.info("🔄 RAG enhancement initialization started in background")

    transport = os.getenv("MCP_TRANSPORT", "stdio").lower()
    if transport == "sse":
        import uvicorn

        host = os.getenv("MCP_HOST", "0.0.0.0")
        port = int(os.getenv("MCP_PORT", "8080"))

        # Mount FastMCP at root so /messages/ and other endpoints work correctly
        app = mcp.http_app(path="/", transport="sse")

        @app.route("/health", methods=["GET"])
        async def healthcheck(_: Request) -> JSONResponse:
            """Lightweight endpoint used for container health checks."""

            return JSONResponse({"status": "ok"})

        logger.info("🌐 Running MCP server on http://%s:%s", host, port)
        logger.info("📡 SSE endpoint available at /sse")
        logger.info("💬 Messages endpoint available at /messages/")
        uvicorn.run(app, host=host, port=port)
    else:
        logger.info("📡 Running MCP server in STDIO mode")
        mcp.run()


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    main()
