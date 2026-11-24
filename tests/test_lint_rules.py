"""T28: project lint rules that ruff cannot express.

`src/domain/` holds the money, ledger and approval rules, which must use `Decimal`
(CLAUDE.md). ruff has no rule that bans the builtin `float`, so this AST check fails
the build if `float` appears anywhere in domain code: annotations, `float(...)`
conversions, `isinstance(x, float)` branches, or float literals such as `0.1`.
"""
import ast
from pathlib import Path

DOMAIN = Path(__file__).resolve().parent.parent / "src" / "domain"


def float_uses(source: str, filename: str = "<src>") -> list[str]:
    hits = []
    for node in ast.walk(ast.parse(source, filename)):
        if isinstance(node, ast.Name) and node.id == "float":
            hits.append(f"{filename}:{node.lineno} uses `float`")
        elif isinstance(node, ast.Constant) and isinstance(node.value, float):
            hits.append(f"{filename}:{node.lineno} float literal {node.value!r}")
        # quoted annotations ("float", "list[float]") are strings, not Names
        ann = getattr(node, "annotation", None) or getattr(node, "returns", None)
        if isinstance(ann, ast.Constant) and isinstance(ann.value, str) and "float" in ann.value:
            hits.append(f"{filename}:{node.lineno} string annotation {ann.value!r}")
    return hits


def test_no_float_in_domain_modules():
    files = sorted(DOMAIN.glob("*.py"))
    assert len(files) >= 5, "domain package moved? update DOMAIN"
    hits = [h for f in files for h in float_uses(f.read_text(encoding="utf-8"), f.name)]
    assert hits == [], "use Decimal / Money in src/domain:\n" + "\n".join(hits)


def test_float_checker_catches_every_form():
    bad = '''
from decimal import Decimal
def fee(amount: float) -> "float":
    if isinstance(amount, float):
        return float(amount) * 0.02
    x: list[float] = []
    return Decimal(0.1)
'''
    hits = float_uses(bad)
    for needle in ("uses `float`", "float literal 0.02", "float literal 0.1", "string annotation 'float'"):
        assert any(needle in h for h in hits), (needle, hits)
    assert float_uses("from decimal import Decimal\nx = Decimal('0.10')\n") == []
