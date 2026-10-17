from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from . import metadata, sbom, vulnscan, score, report, history, ai
from .metadata import DockerError
from .sbom import SyftError
from .vulnscan import TrivyError, GrypeError
from .ai import AIError

INDEX_HTML_PATH = Path(__file__).parent / "static" / "index.html"

app = FastAPI(title="Nicymage API")


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML_PATH.read_text(encoding="utf-8")


class ScanRequest(BaseModel):
    image: str


@app.post("/scan")
def scan(request: ScanRequest) -> dict:
    image = request.image
    try:
        image_metadata = metadata.get_image_metadata(image)
        packages = sbom.generate_sbom(image)
        vulnerabilities = vulnscan.scan_vulnerabilities(image)
        risk = score.compute_risk_score(vulnerabilities)
    except (NotImplementedError, DockerError, SyftError, TrivyError, GrypeError) as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    severity_counts = report.count_by_severity(vulnerabilities)

    try:
        analysis = ai.generate_analysis(vulnerabilities, risk)
    except AIError as exc:
        analysis = f"unavailable ({exc})"

    history.record_scan(image, image_metadata.get("digest"), risk, severity_counts)

    return {
        "image": image,
        "digest": image_metadata.get("digest"),
        "packages": len(packages),
        "vulnerabilities": severity_counts,
        "score": risk.get("score"),
        "verdict": risk.get("verdict"),
        "ai_analysis": analysis,
    }


@app.get("/history/{image:path}")
def get_history(image: str) -> list:
    return history.get_history(image)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
