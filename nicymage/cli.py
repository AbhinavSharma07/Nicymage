import argparse
import sys

from . import metadata, sbom, vulnscan, score, report, history, ai
from .metadata import DockerError
from .sbom import SyftError
from .vulnscan import TrivyError, GrypeError
from .ai import AIError


def build_parser():
    parser = argparse.ArgumentParser(prog="nicymage", description="Local-first container image security auditor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a container image")
    scan_parser.add_argument("image", help="Image reference to scan, e.g. nginx:latest")

    history_parser = subparsers.add_parser("history", help="Show past scans of an image")
    history_parser.add_argument("image", help="Image reference to look up, e.g. nginx:latest")

    return parser


def run_scan(image: str) -> int:
    try:
        image_metadata = metadata.get_image_metadata(image)
        packages = sbom.generate_sbom(image)
        vulnerabilities = vulnscan.scan_vulnerabilities(image)
        risk = score.compute_risk_score(vulnerabilities)
        severity_counts = report.render_report(image_metadata, packages, vulnerabilities, risk)
    except (NotImplementedError, DockerError, SyftError, TrivyError, GrypeError) as exc:
        print(f"nicymage: {exc}", file=sys.stderr)
        return 1

    print()
    print("AI Analysis:")
    try:
        print(ai.generate_analysis(vulnerabilities, risk))
    except AIError as exc:
        print(f"unavailable ({exc})")

    history.record_scan(image, image_metadata.get("digest"), risk, severity_counts)
    return 2 if risk["verdict"] == "HIGH" else 0


def run_history(image: str) -> int:
    records = history.get_history(image)
    if not records:
        print(f"No scan history for {image}")
        return 0

    for record in records:
        print(
            f"{record['timestamp']}  score={record['score']}  verdict={record['verdict']}  "
            f"digest={record['digest']}  "
            f"C={record['critical']} H={record['high']} M={record['medium']} L={record['low']}"
        )
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args.image)
    if args.command == "history":
        return run_history(args.image)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
