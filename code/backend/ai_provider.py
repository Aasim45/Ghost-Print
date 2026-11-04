"""Optional, user-triggered OpenAI-compatible case explanations."""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

CODE_DIR = Path(__file__).resolve().parents[1]


def _load_local_env() -> None:
    env_file = CODE_DIR / ".env"
    if not env_file.is_file():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip("\"'")
        if key and key.replace("_", "a").isalnum() and key not in os.environ:
            os.environ[key] = value


def configuration() -> dict:
    _load_local_env()
    key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY", "")
    model = "gpt-4.1-mini"
    base = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    endpoint = os.getenv("LLM_CHAT_COMPLETIONS_URL") or f"{base}/chat/completions"
    provider = os.getenv("LLM_PROVIDER") or ("OpenAI" if os.getenv("OPENAI_API_KEY") else "OpenAI-compatible")
    return {"enabled": bool(key), "key": key, "model": model, "endpoint": endpoint, "provider": provider}


def explain_case(case: dict) -> dict:
    config = configuration()
    if not config["enabled"]:
        return {"configured": False, "provider": config["provider"], "model": config["model"] or None,
                "explanation": None, "message": "AI explanations are not configured. Set LLM_API_KEY in code/.env, then restart the server."}

    findings = case.get("findings") or []
    facts = {
        "status": case.get("deletion_status"),
        "audit_cutoff": (case.get("request") or {}).get("audit_at", ""),
        "evidence_gap": bool(not findings and case.get("deletion_status") == "INCOMPLETE"),
        "findings": [{
            "finding_number": index,
            "operation": str(item.get("operation", ""))[:80],
            "system": str(item.get("system_id", ""))[:80],
            "resource_type": str(item.get("data_category", ""))[:60],
            "policy_action": str(item.get("policy_action", ""))[:100],
            "evidence_reference": str(item.get("evidence_id", ""))[:80],
        } for index, item in enumerate(findings, 1)],
    }
    body = json.dumps({
        "model": config["model"], "temperature": 0.1, "max_tokens": 350,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": "Explain this deletion audit in concise plain language using only the supplied facts. Never decide or alter status, invent systems, identifiers, evidence, policies, findings, or actions. If evidence_gap is true, say absence is unverified rather than claiming data remains. Return JSON with summary (string) and points (at most 4 strings)."},
            {"role": "user", "content": json.dumps(facts)},
        ],
    }).encode("utf-8")
    request = Request(config["endpoint"], data=body, headers={"Authorization": f"Bearer {config['key']}", "Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=25) as response:
            payload = json.loads(response.read())
    except HTTPError as exc:
        return {"configured": True, "provider": config["provider"], "model": config["model"], "explanation": None,
                "message": f"AI provider returned HTTP {exc.code}. Check the provider URL, model, and key."}
    except (URLError, TimeoutError, OSError):
        return {"configured": True, "provider": config["provider"], "model": config["model"], "explanation": None,
                "message": "AI service could not be reached (network error or timeout)."}
    try:
        content = payload["choices"][0]["message"]["content"]
        result = json.loads(content)
        summary = result.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            raise ValueError("Missing summary")
        points = result.get("points", [])
        if not isinstance(points, list):
            points = []
        return {"configured": True, "provider": config["provider"], "model": config["model"],
                "explanation": {"summary": summary[:1200], "points": [p[:400] for p in points if isinstance(p, str)][:4]},
                "usage": payload.get("usage")}
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return {"configured": True, "provider": config["provider"], "model": config["model"], "explanation": None,
                "message": "AI provider response did not match the required explanation format."}
