import json
import subprocess


class TrivyError(Exception):
    pass


class GrypeError(Exception):
    pass


def _scan_with_trivy(image: str) -> list:
    try:
        result = subprocess.run(
            ["trivy", "image", image, "-f", "json"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise TrivyError("Trivy is not installed or not on PATH")

    if result.returncode != 0:
        raise TrivyError(f"trivy failed: {result.stderr.strip()}")

    data = json.loads(result.stdout)

    findings = []
    for target_result in data.get("Results", []) or []:
        for vuln in target_result.get("Vulnerabilities", []) or []:
            findings.append({
                "package": vuln.get("PkgName"),
                "cve_id": vuln.get("VulnerabilityID"),
                "severity": vuln.get("Severity"),
                "fixed_version": vuln.get("FixedVersion"),
            })
    return findings


def _scan_with_grype(image: str) -> list:
    try:
        result = subprocess.run(
            ["grype", image, "-o", "json"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise GrypeError("Grype is not installed or not on PATH")

    if result.returncode != 0:
        raise GrypeError(f"grype failed: {result.stderr.strip()}")

    data = json.loads(result.stdout)

    findings = []
    for match in data.get("matches", []) or []:
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        fix = vulnerability.get("fix", {})
        fixed_versions = fix.get("versions") or []
        findings.append({
            "package": artifact.get("name"),
            "cve_id": vulnerability.get("id"),
            "severity": (vulnerability.get("severity") or "UNKNOWN").upper(),
            "fixed_version": fixed_versions[0] if fix.get("state") == "fixed" and fixed_versions else None,
        })
    return findings


def _merge_findings(trivy_findings: list, grype_findings: list) -> list:
    combined = {}
    for finding in trivy_findings:
        key = (finding.get("package"), finding.get("cve_id"))
        combined[key] = dict(finding, sources=["trivy"])

    for finding in grype_findings:
        key = (finding.get("package"), finding.get("cve_id"))
        if key in combined:
            combined[key]["sources"].append("grype")
        else:
            combined[key] = dict(finding, sources=["grype"])

    return list(combined.values())


def scan_vulnerabilities(image: str) -> list:
    trivy_findings = _scan_with_trivy(image)
    grype_findings = _scan_with_grype(image)
    return _merge_findings(trivy_findings, grype_findings)
