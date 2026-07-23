"""Test KoboldCpp with new textual ReAct prompt."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
from services.agent.prompts import generate_system_prompt_with_tools
from services.agent_tools import _TOOLS_BASIC

system = generate_system_prompt_with_tools(_TOOLS_BASIC)

payload = {
    "model": "Qwen3.5-4B-Q4_K_S.gguf",
    "messages": [
        {"role": "system", "content": system},
        {"role": "user", "content": "מה המצב של המערכת?"}
    ],
    "temperature": 0.3,
    "max_tokens": 150
}

print("System prompt length:", len(system), "chars")
print("Sending to KoboldCpp...")
resp = requests.post("http://127.0.0.1:5001/v1/chat/completions", json=payload, timeout=30)
print("Status:", resp.status_code)
content = resp.json()["choices"][0]["message"]["content"]
print("Response:")
print(content)
print("---")
print("Length:", len(content))
