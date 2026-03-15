"""
ThreatPulse — AI Security Summary Generator
Uses OpenRouter API with fallback model chain.
"""
import os
import requests
from dotenv import load_dotenv

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(PROJECT_ROOT, '.env'), override=True)

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Models to try in order — first success wins (verified free on OpenRouter)
MODELS = [
    "google/gemma-3n-e4b-it:free",
    "nvidia/nemotron-nano-9b-v2:free",
    "qwen/qwen3-coder:free",
    "z-ai/glm-4.5-air:free",
    "openai/gpt-oss-20b:free",
]


def generate_security_summary(event_details: dict) -> str:
    """
    Generates a concise security summary using OpenRouter AI.
    Tries multiple free models as fallbacks.
    """
    api_key = os.getenv("OPENROUTER_API_KEY", "")
    if not api_key:
        return "AI summary unavailable — OPENROUTER_API_KEY not set."

    prompt = f"""You are a Cyber Security Analyst looking at a high-risk event.
Summarize the following security log into a short, actionable explanation for a SOC team.

Event Details:
- User: {event_details.get('user')}
- Action: {event_details.get('action')}
- Status: {event_details.get('status')}
- Resource: {event_details.get('resource')}
- Attack Type: {event_details.get('attack_type', 'unknown')}
- Risk Score: {event_details.get('risk_score')}
- Context: {event_details.get('explanation')}

Explain:
1. What happened?
2. Why is it suspicious?
3. Recommended immediate action.

Keep it brief (max 3-4 sentences)."""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "https://github.com/threatpulse",
        "X-Title": "ThreatPulse SOC",
        "Content-Type": "application/json",
    }

    for model in MODELS:
        try:
            payload = {
                "model": model,
                "messages": [
                    {"role": "user", "content": "You are a cybersecurity SOC analyst. Be concise and actionable.\n\n" + prompt},
                ],
                "temperature": 0.3,
                "max_tokens": 300,
            }

            response = requests.post(
                f"{OPENROUTER_BASE_URL}/chat/completions",
                headers=headers,
                json=payload,
                timeout=15,
            )

            if response.status_code == 200:
                data = response.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                if content:
                    return content

            # 405/429/503 = try next model
            if response.status_code in (405, 429, 503):
                continue

            # Other errors — return the error but don't crash
            return f"AI Summary Error ({response.status_code}): {response.text[:150]}"

        except requests.exceptions.Timeout:
            continue
        except Exception as e:
            continue

    return "AI summary unavailable — all models failed. Check your OpenRouter API key."
