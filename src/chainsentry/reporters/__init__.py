"""Reporters: turn a ``ScanResult`` into output for humans and machines.

Modules:
    summary       totals shared by every reporter (one source of truth)
    table         coloured terminal output (rich)
    json_report   stable JSON report (read by the dashboard, batch mode, Action)
    cyclonedx     CycloneDX 1.5 SBOM with a vulnerabilities section
    markdown      compact report for GitHub PR comments / job summaries
"""
