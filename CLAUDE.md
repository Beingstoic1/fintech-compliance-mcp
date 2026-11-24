# Project Rules: fintech-compliance-mcp
- Always read `.memory/HANDOFF.md` before starting work and update it before finishing.
- Never trust `user_id`, `role`, or `tenant_id` supplied in LLM tool arguments; identity must come from verified session/token headers.
- Use Python `Decimal` for all monetary values; never use `float`.
- Keep business rules (thresholds, masking, ledger math) in pure domain modules, separate from FastMCP/FastAPI/Streamlit handlers.
- Never log raw PII, auth tokens, or secrets in audit payloads.
- Run `pytest` after every code change and paste real pass/fail output into `.memory/HANDOFF.md`.
