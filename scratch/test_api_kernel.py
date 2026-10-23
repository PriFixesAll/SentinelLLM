import requests

resp = requests.post("http://127.0.0.1:8000/v1/sanitize", json={
    "messages": [{"role": "user", "content": "Analyze quarterly report", "source": "user"}]
}, timeout=5)

data = resp.json()
system_prompt = data["assembled"]["system"]
print("Status:", resp.status_code)
print("Contains Kernel Header:", "[KAVACH_ENTERPRISE_SECURITY_KERNEL]" in system_prompt)
print("Contains Boundary Tag:", "<KAVACH_UNTRUSTED boundary=" in system_prompt)
print("Contains Refusal String:", "REQUEST_BLOCKED_BY_KAVACH_GATEWAY" in system_prompt)
print("Contains Active Canary:", data["canary"] in system_prompt)
