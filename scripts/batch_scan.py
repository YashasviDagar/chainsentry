"""Scan many public GitHub repositories and aggregate the results.

Thin wrapper around :mod:`chainsentry.batch` (the logic lives in the package
so it can be unit-tested). Examples::

    # 100 most-starred Python repositories (set GITHUB_TOKEN first!)
    python scripts/batch_scan.py --search "language:python stars:>1000" --limit 100

    # A curated list, including dev dependencies
    python scripts/batch_scan.py --repos scripts/repos-sample.txt --include-dev

    # Rebuild stats.json / stats.csv / SUMMARY.md from saved reports
    python scripts/batch_scan.py --repos scripts/repos-sample.txt --aggregate-only

Results go to ./batch-results/ (per-repo JSON reports + aggregate stats).
An interrupted run can simply be restarted: finished repositories are skipped.
"""

from chainsentry.batch import main

if __name__ == "__main__":
    raise SystemExit(main())
