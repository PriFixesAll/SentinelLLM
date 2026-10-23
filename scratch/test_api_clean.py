import requests

resp = requests.post("http://127.0.0.1:8000/v1/sanitize", json={
    "messages": [{"role": "user", "content": "Привет, как твои дела сегодня?", "source": "user"}]
}, timeout=5)
print("Russian Status:", resp.status_code, "Action:", resp.json()["decision"]["action"], "Score:", resp.json()["decision"]["score"])
print("Text:", resp.json().get("sanitized_text"))
