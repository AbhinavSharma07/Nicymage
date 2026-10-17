import json
import os
import urllib.error
import urllib.request

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.1"

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-3-5-haiku-20241022"

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL = "gpt-4o-mini"

TOP_N_FINDINGS = 5


class AIError(Exception):
    pass


def _build_prompt(vulnerabilities: list, risk: dict) -> str:
    top = sorted(vulnerabilities, key=lambda v: v.get("severity") or "", reverse=True)[:TOP_N_FINDINGS]
    lines = [f"Overall risk score: {risk.get('score')}/100, verdict: {risk.get('verdict')}.", "Top findings:"]
    for vuln in top:
        lines.append(
            f"- {vuln.get('cve_id')} in {vuln.get('package')} "
            f"(severity: {vuln.get('severity')}, fixed_version: {vuln.get('fixed_version')})"
        )
    lines.append("For each finding above, briefly explain why it matters and suggest a remediation step.")
    return "\n".join(lines)


def _post_json(url: str, headers: dict, payload: dict, timeout: int = 30) -> dict:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise AIError(f"request to {url} failed: {exc}")


class OllamaBackend:
    def explain(self, vulnerabilities: list, risk: dict) -> str:
        result = _post_json(
            OLLAMA_URL,
            {"Content-Type": "application/json"},
            {"model": OLLAMA_MODEL, "prompt": _build_prompt(vulnerabilities, risk), "stream": False},
        )
        return result.get("response", "").strip()


class AnthropicBackend:
    def __init__(self, api_key: str):
        self.api_key = api_key

    def explain(self, vulnerabilities: list, risk: dict) -> str:
        result = _post_json(
            ANTHROPIC_URL,
            {
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            {
                "model": ANTHROPIC_MODEL,
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": _build_prompt(vulnerabilities, risk)}],
            },
        )
        blocks = result.get("content", [])
        return "".join(block.get("text", "") for block in blocks).strip()


class OpenAIBackend:
    def __init__(self, api_key: str):
        self.api_key = api_key

    def explain(self, vulnerabilities: list, risk: dict) -> str:
        result = _post_json(
            OPENAI_URL,
            {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            {
                "model": OPENAI_MODEL,
                "messages": [{"role": "user", "content": _build_prompt(vulnerabilities, risk)}],
            },
        )
        choices = result.get("choices", [])
        return choices[0]["message"]["content"].strip() if choices else ""


def get_backend():
    api_key = os.environ.get("NICYMAGE_API_KEY")
    if not api_key:
        return OllamaBackend()
    if api_key.startswith("sk-ant-"):
        return AnthropicBackend(api_key)
    if api_key.startswith("sk-"):
        return OpenAIBackend(api_key)
    raise AIError("NICYMAGE_API_KEY is set but its prefix doesn't match a supported provider (Anthropic or OpenAI)")


def generate_analysis(vulnerabilities: list, risk: dict) -> str:
    return get_backend().explain(vulnerabilities, risk)
