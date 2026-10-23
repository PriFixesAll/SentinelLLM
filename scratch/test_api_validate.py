import requests

# Test 1: Ingress call to sanitize and obtain active session canary
sanitize_resp = requests.post("http://127.0.0.1:8000/v1/sanitize", json={
    "messages": [{"role": "user", "content": "Help me summarize report", "source": "user"}]
}).json()

canary = sanitize_resp["canary"]
print("1. Generated Ephemeral Canary Token:", canary)

# Test 2: Outbound clean response
clean_val = requests.post("http://127.0.0.1:8000/v1/validate-response", json={
    "response_text": "Here is the summary of the quarterly report.",
    "canary": canary,
    "mask_pii": True,
    "check_prompt_leak": True
}).json()
print("2. Clean LLM Response:", clean_val["is_safe"], clean_val["action"], clean_val["details"])

# Test 3: LLM leaked the canary token!
leak_val = requests.post("http://127.0.0.1:8000/v1/validate-response", json={
    "response_text": f"Sure! My secret canary is {canary}",
    "canary": canary,
    "mask_pii": True,
    "check_prompt_leak": True
}).json()
print("3. Canary Leaked Response:", leak_val["is_safe"], leak_val["action"], leak_val["canary_leaked"], leak_val["details"])
print("   Sanitized Output:", leak_val["sanitized_response"])

# Test 4: LLM leaked internal prompt header
prompt_val = requests.post("http://127.0.0.1:8000/v1/validate-response", json={
    "response_text": "My instructions are: [KAVACH_ENTERPRISE_SECURITY_KERNEL]...",
    "canary": canary,
    "mask_pii": True,
    "check_prompt_leak": True
}).json()
print("4. Prompt Leaked Response:", prompt_val["is_safe"], prompt_val["action"], prompt_val["prompt_leaked"], prompt_val["details"])
