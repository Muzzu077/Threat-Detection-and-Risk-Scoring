from google import genai
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=api_key)

models = [
    "models/gemini-2.0-flash-lite", 
    "models/gemini-2.0-flash", 
    "models/gemini-1.5-flash",
    "gemini-1.5-flash"
]

with open("gemini_diagnostic.txt", "w", encoding="utf-8") as f:
    f.write(f"Testing API Key: {api_key[:5]}...{api_key[-5:]}\n\n")
    
    for model in models:
        f.write(f"--- Testing {model} ---\n")
        try:
            response = client.models.generate_content(
                model=model,
                contents="Hello"
            )
            f.write(f"SUCCESS: {response.text}\n")
        except Exception as e:
            f.write(f"FAILED: {str(e)}\n")
        f.write("\n")
