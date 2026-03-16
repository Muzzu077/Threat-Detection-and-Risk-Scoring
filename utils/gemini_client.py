import os
import requests
from dotenv import load_dotenv

# Load env variables
load_dotenv()

SAMBANOVA_API_KEY = os.getenv("SAMBANOVA_API_KEY")
SAMBANOVA_BASE_URL = "https://api.sambanova.ai/v1"

def generate_security_summary(event_details):
    """
    Generates a concise security summary using SambaNova AI.
    """
    if not SAMBANOVA_API_KEY:
        return "⚠️ SambaNova API Key not found. AI summary unavailable."

    prompt = f"""You are a Cyber Security Analyst looking at a high-risk event.
Summarize the following security log into a short, actionable explanation for a SOC team.

Event Details:
- User: {event_details.get('user')}
- Action: {event_details.get('action')}
- Status: {event_details.get('status')}
- Resource: {event_details.get('resource')}
- Risk Score: {event_details.get('risk_score')}
- Context: {event_details.get('explanation')}

Explain:
1. What happened?
2. Why is it suspicious?
3. Recommended immediate action.

Keep it brief (max 3-4 sentences)."""

    try:
        headers = {
            "Authorization": f"Bearer {SAMBANOVA_API_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": "Meta-Llama-3.3-70B-Instruct",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity SOC analyst. Be concise and actionable."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "top_p": 0.1
        }

        response = requests.post(
            f"{SAMBANOVA_BASE_URL}/chat/completions",
            headers=headers,
            json=payload,
            timeout=15
        )

        if response.status_code == 200:
            data = response.json()
            return data["choices"][0]["message"]["content"]
        else:
            return f"⚠️ AI Summary Error ({response.status_code}): {response.text[:150]}"

    except Exception as e:
        return f"⚠️ Error generating AI summary: {str(e)}"
