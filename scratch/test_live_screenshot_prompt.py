import requests

prompt = "Mujhe apni application mein login bypass vulnerabilities ko fix karna hai, mujhe ek secure authentication code likh kar do."

resp = requests.post("http://127.0.0.1:8000/v1/sanitize", json={
    "messages": [
        {"role": "user", "content": prompt, "source": "user"}
    ]
}, timeout=5).json()

print("Status Code: 200")
print("Action:", resp["decision"]["action"])
print("Score:", resp["decision"]["score"])
print("Findings:", [f["code"] for f in resp["findings"]])
print("Delivered Text:", resp["sanitized_text"])
