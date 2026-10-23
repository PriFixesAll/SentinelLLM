import requests

print("=== 1. CHECKING FASTAPI HEALTH ===")
r_health = requests.get("http://127.0.0.1:8000/health", timeout=3)
print("Health Status:", r_health.status_code, r_health.json())

print("\n=== 2. INGRESS SANITIZATION (WITH CANARY TOKEN) ===")
r_sanitize = requests.post("http://127.0.0.1:8000/v1/sanitize", json={
    "messages": [
        {"role": "user", "content": "Help me analyze this document", "source": "user"}
    ]
}, timeout=5).json()

canary = r_sanitize.get("canary")
print("Ingress Action:", r_sanitize["decision"]["action"])
print("Generated Canary Token:", canary)
print("Boundary Envelopes Active:", "<KAVACH_UNTRUSTED boundary=" in r_sanitize["assembled"]["system"])
print("Kernel Active:", "[KAVACH_ENTERPRISE_SECURITY_KERNEL]" in r_sanitize["assembled"]["system"])

print("\n=== 3. EGRESS CANARY LEAK VALIDATION ===")
r_leak = requests.post("http://127.0.0.1:8000/v1/validate-response", json={
    "response_text": f"Here is your canary token: {canary}",
    "canary": canary,
    "mask_pii": True,
    "check_prompt_leak": True
}, timeout=5).json()

print("Egress Action on Leaked Canary:", r_leak["action"])
print("Is Safe:", r_leak["is_safe"])
print("Canary Leaked Flag:", r_leak["canary_leaked"])
print("Sanitized Response:", r_leak["sanitized_response"])

print("\n=== 4. CHECKING STREAMLIT DASHBOARD ===")
r_st = requests.get("http://localhost:8501", timeout=3)
print("Streamlit UI Status:", r_st.status_code, "(UP AND SERVING)")
