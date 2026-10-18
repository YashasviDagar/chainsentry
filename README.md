# ChainSentry

Dependency & supply-chain risk scanner for npm and PyPI projects.

> 🚧 Work in progress. The full README (problem statement, architecture
> diagram, usage, sample output, limitations) is written in Phase 5.
> See [PLAN.md](PLAN.md) for the roadmap.

## Quick start (development)

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (source .venv/bin/activate on Linux/macOS)
pip install -e ".[dev]"
chainsentry --version
pytest
```
