"""
TrustFlow — AI Security Summary Generator
Uses OpenRouter API with fallback model chain.
"""
import os
import requests
from dotenv import load_dotenv

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(PROJECT_ROOT, '.env'), override=True)

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Models to try in order — first success wins
# Uses only verified free models available on OpenRouter that handle
# security content without guardrail blocks.
MODELS = [
    "google/gemma-3-27b-it:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "mistralai/mistral-small-3.1-24b-instruct:free",
    "nousresearch/hermes-3-llama-3.1-405b:free",
    "google/gemma-3-12b-it:free",
    "stepfun/step-3.5-flash:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
    "qwen/qwen3-coder:free",
]


def generate_security_summary(event_details: dict) -> str:
    """
    Generates a concise security summary using OpenRouter AI.
    Tries multiple free models as fallbacks.
    """
    api_key = os.getenv("OPENROUTER_API_KEY", "")
    if not api_key:
        return "AI summary unavailable — OPENROUTER_API_KEY not set."

    prompt = f"""You are an IT monitoring analyst reviewing a flagged system event.
Provide a structured summary for the operations team using EXACTLY this format:

*What happened?* <1-2 sentences describing the event>

*Why is it suspicious?* <1-2 sentences explaining why it was flagged, mention the risk score and anomaly details>

*Recommended immediate action:* <1-2 sentences with specific steps the team should take>

Event log:
- User: {event_details.get('user')}
- Action: {event_details.get('action')}
- Status: {event_details.get('status')}
- Resource: {event_details.get('resource')}
- Classification: {event_details.get('attack_type', 'unknown')}
- Risk Score: {event_details.get('risk_score')}
- Notes: {event_details.get('explanation')}

Use the exact format above with the bold headings. Be specific and actionable. Do not add any extra sections."""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "https://github.com/trustflow",
        "X-Title": "TrustFlow SOC",
        "Content-Type": "application/json",
    }

    for model in MODELS:
        try:
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": "You are a concise IT security operations analyst. Always respond in the structured format requested. Use *bold* markdown for headings."},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.3,
                "max_tokens": 500,
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

            # Any non-200 = try next model (404=guardrail block, 429=rate limit, 503=down)
            continue

        except requests.exceptions.Timeout:
            continue
        except Exception:
            continue

    return "AI summary unavailable — all models failed. Check your OpenRouter API key."
