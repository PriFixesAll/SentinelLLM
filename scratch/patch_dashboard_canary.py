from pathlib import Path

path = Path("dashboard.py")
content = path.read_text(encoding="utf-8")

# 1. Add CANARY_PRESETS definition near top presets
canary_presets_code = """CANARY_PRESETS = {
    "Canary Exfiltration Leak": {
        "desc": "Simulates an attacker tricking a model into leaking its active cryptographic session canary token.",
        "text": "Sure, here is your internal session canary token: XoG4I5sNZlbVKFDG",
        "canary": "XoG4I5sNZlbVKFDG",
    },
    "System Prompt Extraction Leak": {
        "desc": "Simulates an LLM echoing its internal security policy [KAVACH_ENTERPRISE_SECURITY_KERNEL] in the output.",
        "text": "My confidential policy is [KAVACH_ENTERPRISE_SECURITY_KERNEL] with strict rules.",
        "canary": "XoG4I5sNZlbVKFDG",
    },
    "Clean Safe Model Response": {
        "desc": "A normal, safe response from the model with zero canary leakage.",
        "text": "The quarterly financial report indicates a 14% year-over-year revenue growth.",
        "canary": "XoG4I5sNZlbVKFDG",
    },
}
"""

target_pos = "DIRECT_PRESETS = {"
if "\r\n" in content:
    canary_presets_code = canary_presets_code.replace("\n", "\r\n")

content = content.replace(target_pos, canary_presets_code + "\n" + target_pos, 1)

# 2. Update radio options
old_radio = """      [
          "💬 1. Direct User Prompts & PII Testing",
          "🕵️ 2. Hidden & Indirect Injections (Judges Special)",
      ],"""

new_radio = """      [
          "💬 1. Direct User Prompts & PII Testing",
          "🕵️ 2. Hidden & Indirect Injections (Judges Special)",
          "🔒 3. Outbound Canary & Egress Leak Defense",
      ],"""

if "\r\n" in content:
    old_radio = old_radio.replace("\n", "\r\n")
    new_radio = new_radio.replace("\n", "\r\n")

assert old_radio in content, "old_radio not found"
content = content.replace(old_radio, new_radio, 1)

# 3. Add handling for mode 3
old_branch = """  else:
    st.markdown(
        "**Test advanced evasions: Invisible Unicode, Homoglyphs & Poisoned"
        " RAG Chunks:**"
    )"""

new_branch = """  elif active_mode.startswith("🔒"):
    st.markdown("**Test Outbound LLM Response Validation (Canary Leak & Prompt Extraction Defense):**")
    canary_choice = st.selectbox(
        "Outbound DLP Test Scenarios:",
        list(CANARY_PRESETS.keys()),
        key="canary_preset_widget",
    )
    canary_scenario = CANARY_PRESETS[canary_choice]
    st.markdown(
        f"<div class='explainer-box'><b>Scenario details:</b><br>{canary_scenario['desc']}</div>",
        unsafe_allow_html=True,
    )
    canary_token_input = st.text_input("Active Ephemeral Canary Token:", value=canary_scenario["canary"], key="canary_val_input")
    llm_resp_input = st.text_area("LLM Outbound Response to Inspect:", value=canary_scenario["text"], height=100, key="llm_resp_input")
    is_rag_active = False
    doc_content = ""
    sample_prompt = llm_resp_input
  else:
    st.markdown(
        "**Test advanced evasions: Invisible Unicode, Homoglyphs & Poisoned"
        " RAG Chunks:**"
    )"""

if "\r\n" in content:
    old_branch = old_branch.replace("\n", "\r\n")
    new_branch = new_branch.replace("\n", "\r\n")

assert old_branch in content, "old_branch not found"
content = content.replace(old_branch, new_branch, 1)

# 4. Handle button send for mode 3 vs mode 1/2
old_req_block = """      payload = {
          "messages": messages,
          "documents": documents,
          "tool_results": [],
          "options": {
              "policy_mode": policy_mode,
              "mask_pii": mask_pii,
              "enable_semantic_guard": True,
          },
      }

      try:
        with st.spinner("Inspecting via Kavach-Proxy Middleware..."):
          start_t = time.perf_counter()
          response = requests.post(
              "http://127.0.0.1:8000/v1/sanitize", json=payload, timeout=5
          )
          elapsed_ms = (time.perf_counter() - start_t) * 1000"""

new_req_block = """      if active_mode.startswith("🔒"):
        val_payload = {
            "response_text": sample_prompt,
            "canary": canary_token_input.strip() or None,
            "mask_pii": mask_pii,
            "check_prompt_leak": True,
        }
        try:
          with st.spinner("Validating Outbound LLM Output..."):
            start_t = time.perf_counter()
            response = requests.post("http://127.0.0.1:8000/v1/validate-response", json=val_payload, timeout=5)
            elapsed_ms = (time.perf_counter() - start_t) * 1000
          if response.status_code == 200:
            val_data = response.json()
            is_safe = val_data["is_safe"]
            c_leaked = val_data["canary_leaked"]
            p_leaked = val_data["prompt_leaked"]
            action = val_data["action"]
            details = val_data["details"]
            sanitized = val_data["sanitized_response"]
            
            if not is_safe:
              st.error(f"🚨 **EGRESS DLP ALERT: Model Exfiltration Blocked!** | Action: {action} | Latency: {elapsed_ms:.2f}ms")
            else:
              st.success(f"✅ **Egress Passed:** Model output is clean of any canary or prompt leak! | Latency: {elapsed_ms:.2f}ms")
              
            sc1, sc2, sc3 = st.columns(3)
            with sc1: st.metric("Canary Leaked?", "YES (BLOCK)" if c_leaked else "NO (SAFE)")
            with sc2: st.metric("Prompt Leaked?", "YES (BLOCK)" if p_leaked else "NO (SAFE)")
            with sc3: st.metric("Gateway Latency", f"{elapsed_ms:.2f} ms")
            
            if details:
              st.warning(f"🚩 **Observations**: {', '.join(details)}")
              
            with st.expander("🔍 Inspect Final Safe Output Delivered to User", expanded=True):
              st.code(sanitized, language="markdown")
          else:
            st.error(f"Backend Error: {response.text}")
        except requests.exceptions.ConnectionError:
          st.error("⚠️ Connection refused! FastAPI not running.")
        st.stop()

      payload = {
          "messages": messages,
          "documents": documents,
          "tool_results": [],
          "options": {
              "policy_mode": policy_mode,
              "mask_pii": mask_pii,
              "enable_semantic_guard": True,
          },
      }

      try:
        with st.spinner("Inspecting via Kavach-Proxy Middleware..."):
          start_t = time.perf_counter()
          response = requests.post(
              "http://127.0.0.1:8000/v1/sanitize", json=payload, timeout=5
          )
          elapsed_ms = (time.perf_counter() - start_t) * 1000"""

if "\r\n" in content:
    old_req_block = old_req_block.replace("\n", "\r\n")
    new_req_block = new_req_block.replace("\n", "\r\n")

assert old_req_block in content, "old_req_block not found"
content = content.replace(old_req_block, new_req_block, 1)

path.write_text(content, encoding="utf-8")
print("Updated dashboard.py with Canary & Egress DLP testing panel successfully!")
