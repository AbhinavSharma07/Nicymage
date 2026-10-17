def count_by_severity(vulnerabilities: list) -> dict:
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for vuln in vulnerabilities:
        severity = (vuln.get("severity") or "UNKNOWN").upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return severity_counts


def render_report(metadata: dict, packages: list, vulnerabilities: list, risk: dict) -> dict:
    severity_counts = count_by_severity(vulnerabilities)

    print(f"Image: {metadata.get('image')}")
    print(f"Digest: {metadata.get('digest')}")
    print()
    print(f"Packages: {len(packages)}")
    print()
    print("Vulnerabilities:")
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        print(f"  {severity}: {severity_counts[severity]}")
    print()
    print(f"Score: {risk.get('score')} / 100")
    print(f"Verdict: {risk.get('verdict')}")

    return severity_counts
