"""T27: threat-model notes exist for maintainers and never reach the LLM vendor."""
import ast
import asyncio
from pathlib import Path

from src.mcp_server import server

ROOT = Path(__file__).resolve().parent.parent
DOCUMENTED_MODULES = sorted(
    p for p in [*(ROOT / "src/domain").glob("*.py"), *(ROOT / "src/db").rglob("*.py")]
    if p.name != "__init__.py"
)


def test_every_tool_handler_has_threat_notes_that_are_not_advertised() -> None:
    tools = asyncio.run(server.mcp.list_tools())
    assert {t.name for t in tools} == set(server._MODEL_FACING)
    for tool in tools:
        assert "Threat model" in (getattr(server, tool.name).__doc__ or ""), tool.name
        assert tool.description == server._MODEL_FACING[tool.name]
        assert "Threat model" not in (tool.description or ""), tool.name


def test_every_domain_and_repository_module_has_a_threat_model() -> None:
    assert DOCUMENTED_MODULES
    missing = [str(p.relative_to(ROOT)) for p in DOCUMENTED_MODULES
               if "Threat model" not in (ast.get_docstring(ast.parse(p.read_text())) or "")]
    assert missing == []
