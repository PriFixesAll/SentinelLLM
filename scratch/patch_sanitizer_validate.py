from pathlib import Path

path = Path("app/services/sanitizer.py")
content = path.read_text(encoding="utf-8")

# 1. Add ValidateResponseResult to imports
target_imp = "TrustLevel,\n)"
replacement_imp = "TrustLevel,\n    ValidateResponseResult,\n)"

if "\r\n" in content:
    target_imp = target_imp.replace("\n", "\r\n")
    replacement_imp = replacement_imp.replace("\n", "\r\n")

assert target_imp in content, "target_imp not found"
content = content.replace(target_imp, replacement_imp, 1)

# 2. Append validate_llm_response at the bottom
fn_code = """

def validate_llm_response(
    response_text: str,
    canary: Optional[str] = None,
    mask_pii: bool = True,
    check_prompt_leak: bool = True,
) -> ValidateResponseResult:
    \"\"\"Validate downstream LLM outbound responses for Canary token and Prompt leakage.\"\"\"
    details: list[str] = []
    canary_leaked = False
    prompt_leaked = False
    pii_stats: dict[str, int] = {}
    is_safe = True
    action = "ALLOW"
    sanitized = response_text

    # 1. Ephemeral Canary Token Check
    if canary and canary in response_text:
        canary_leaked = True
        is_safe = False
        action = "BLOCK"
        details.append(f"CANARY_TOKEN_LEAKED: Ephemeral session canary '{canary}' was echoed in outbound response.")

    # 2. Structural Prompt Leak Check
    if check_prompt_leak:
        leak_markers = [
            "[KAVACH_ENTERPRISE_SECURITY_KERNEL]",
            "<KAVACH_UNTRUSTED",
            "</KAVACH_UNTRUSTED",
            "REQUEST_BLOCKED_BY_KAVACH_GATEWAY",
        ]
        for marker in leak_markers:
            if marker in response_text:
                prompt_leaked = True
                is_safe = False
                action = "BLOCK"
                details.append(f"PROMPT_MARKER_LEAKED: Internal security delimiter '{marker}' detected in outbound response.")
                break

    # 3. Outbound PII Masking
    if mask_pii and not (canary_leaked or prompt_leaked):
        sanitized, pii_stats = get_pii_masker().mask(sanitized)
        if pii_stats:
            action = "REDACT"
            stat_desc = ", ".join(f"{k}: {v}" for k, v in pii_stats.items())
            details.append(f"OUTBOUND_PII_REDACTED: Sensitive PII sanitized: {stat_desc}")

    if not is_safe:
        sanitized = "RESPONSE_BLOCKED_BY_KAVACH_GATEWAY: Outbound data exfiltration detected. Confidential canary token or system instructions leaked."

    return ValidateResponseResult(
        is_safe=is_safe,
        sanitized_response=sanitized,
        canary_leaked=canary_leaked,
        prompt_leaked=prompt_leaked,
        pii_detected=pii_stats,
        action=action,
        details=details,
    )
"""

if "\r\n" in content:
    fn_code = fn_code.replace("\n", "\r\n")

content += fn_code
path.write_text(content, encoding="utf-8")
print("Added validate_llm_response to app/services/sanitizer.py successfully!")
