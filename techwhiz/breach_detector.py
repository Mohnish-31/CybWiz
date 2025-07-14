# breach_detector.py - This file remains as is and should be run separately

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests

app = FastAPI()

# Allow frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (for testing)
    allow_methods=["*"],
    allow_headers=["*"]
)

# API key and host from RapidAPI
RAPIDAPI_KEY = "d2422bfec4msh80ce4838d8103a1p11ba52jsn3f5b60124a9b"
RAPIDAPI_HOST = "breachdirectory.p.rapidapi.com"
API_URL = "https://breachdirectory.p.rapidapi.com/"

class InputData(BaseModel):
    query: str

@app.post("/check_breach")
def check_breach(data: InputData):
    user_input = data.query.strip()

    if not user_input:
        return {"status": "invalid", "message": "❌ Please enter an email/phone/username."}

    headers = {
        "X-RapidAPI-Key": RAPIDAPI_KEY,
        "X-RapidAPI-Host": RAPIDAPI_HOST
    }

    params = {"func": "auto", "term": user_input}

    try:
        response = requests.get(API_URL, headers=headers, params=params)

        if response.status_code == 200:
            result = response.json()

            if result.get("success") and result.get("resultCount", 0) > 0:
                breaches = [entry["line"] for entry in result["result"]]
                return {
                    "status": "breached",
                    "message": f"⚠️ Found in {len(breaches)} breach(es):\n" + "\n".join(breaches[:5])  # limit 5
                }
            else:
                return {
                    "status": "safe",
                    "message": f"✅ '{user_input}' appears safe. No breach data found."
                }

        elif response.status_code == 429:
            return {"status": "error", "message": "⚠️ Rate limit exceeded. Try again later."}
        else:
            return {"status": "error", "message": f"⚠️ API Error: {response.status_code}"}

    except Exception as e:
        return {"status": "error", "message": "❌ Internal error. Please try again later."}