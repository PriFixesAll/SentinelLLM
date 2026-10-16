import time
import requests
import streamlit as st

st.set_page_config(
    page_title="Kavach-Proxy Security Dashboard", page_icon="🛡️", layout="wide"
)

# Custom Styling for modern look
st.markdown(
    """
    <style>
    .main { background-color: #0f172a; color: #f8fafc; }
    .stAlert { border-radius: 8px; }
    </style>
""",
    unsafe_allow_html=True,
)

st.title("🛡️ Kavach-Proxy: Live Enterprise Security Gateway")
st.markdown(
    "**Middleware Defense Layer** protecting LLM applications from Prompt "
    "Injections & Structural Tampering in real-time."
)

# Layout Columns
col_left, col_right = st.columns([1.2, 0.8])

with col_left:
  st.subheader("💬 Simulated LLM Chat Interface")
  st.markdown(
      "Test how Kavach-Proxy intercepts user traffic before it reaches the"
      " LLM."
  )

  sample_prompt = st.text_area(
      "Enter user prompt or untrusted data:",
      "Hello! Can you help me analyze this quarterly report?",
      height=120,
  )

  policy_mode = st.selectbox("Proxy Policy Mode", ["enforce", "monitor"])

  if st.button("Send Request through Proxy 🚀", type="primary"):
    if not sample_prompt.strip():
      st.warning("Please enter some text.")
    else:
      payload = {
          "messages": [
              {"role": "user", "content": sample_prompt, "source": "user"}
          ],
          "documents": [],
          "tool_results": [],
          "options": {"policy_mode": policy_mode},
      }

      try:
        with st.spinner("Inspecting via Kavach-Proxy Middleware..."):
          time.sleep(0.3)  # smooth animation effect
          response = requests.post(
              "http://127.0.0.1:8000/v1/sanitize", json=payload
          )

        if response.status_code == 200:
          data = response.json()
          decision = data.get("decision", {})
          action = decision.get("action", "PASS")
          score = decision.get("risk_score", decision.get("score", 0.0))
          reasons = decision.get("matches", decision.get("reasons", []))

          # Store in session state for live audit feed
          if "history" not in st.session_state:
            st.session_state.history = []
          st.session_state.history.insert(
              0,
              {
                  "prompt": sample_prompt,
                  "action": action,
                  "score": score,
                  "reasons": reasons,
              },
          )

          # Visual Notification Alerts on UI
          if action.upper() == "BLOCK":
            st.error(
                "🚨 **SECURITY ALERT: Prompt Injection Blocked!** Attack pattern"
                f" detected (Risk Score: {score})"
            )
          elif action.upper() == "REDACT":
            st.warning(
                "⚠️ **Warning: Content Redacted!** Medium risk detected (Risk"
                f" Score: {score})"
            )
          else:
            st.success(
                "✅ **Traffic Clean:** Request passed safely to LLM (Risk Score:"
                f" {score})"
            )

        else:
          st.error(f"Backend Error: {response.text}")

      except requests.exceptions.ConnectionError:
        st.error(
            "⚠️ **Connection Refused!** Make sure your FastAPI backend server"
            " is running (`uvicorn app.main:app --reload`)."
        )

with col_right:
  st.subheader("📊 Live Security Audit Feed")
  st.markdown("Real-time inspection telemetry captured by the proxy.")

  if "history" in st.session_state and st.session_state.history:
    for item in st.session_state.history[:5]:  # show last 5 events
      act_upper = item["action"].upper()
      status_color = "🔴" if act_upper == "BLOCK" else "🟢"
      with st.container():
        st.markdown(f"""
                **{status_color} Action: `{act_upper}`** | **Risk Score:** `{item['score']}`
                * *Input:* `{item['prompt'][:60]}...`
                * *Flags:* `{item['reasons'] if item['reasons'] else 'None'}`
                ---
                """)
  else:
    st.info(
        "No requests processed yet. Try sending a prompt from the left panel!"
    )