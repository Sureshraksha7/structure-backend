import requests
import json

# ✅ Your new Google API key
GOOGLE_API_KEY = "AIzaSyDWVDzIVdPWIbtcgwZtWo6XNkxCjYi8ppo"

# ✅ Updated API URL for Google's Gemini 2.5 Flash model
API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key={GOOGLE_API_KEY}"

# Example input
category = "healthcare"
num_pages = 20
prompt = f"Generate a hierarchical website structure with about {num_pages} pages for a website in the '{category}' category. Include main pages and subpages."

# ✅ Defined the JSON schema we want the AI to return
# This forces the output to be clean JSON
json_schema = {
    "type": "ARRAY",
    "items": {
        "type": "OBJECT",
        "properties": {
            "page": { "type": "STRING" },
            "subpages": {
                "type": "ARRAY",
                "items": {
                        "type": "OBJECT",
                        "properties": {
                        "page": { "type": "STRING" },
                        "subpages": { "type": "ARRAY" } # Allows for nested pages
                        }
                }
            }
        },
        "required": ["page", "subpages"]
    }
}

# ✅ Updated payload for the Gemini API
payload = {
    "contents": [
        { "parts": [{ "text": prompt }] }
    ],
    "generationConfig": {
        "responseMimeType": "application/json", # Force JSON output
        "responseSchema": json_schema          # Use our defined schema
    }
}

# ✅ Updated headers for Google API
headers = {
    "Content-Type": "application/json"
}