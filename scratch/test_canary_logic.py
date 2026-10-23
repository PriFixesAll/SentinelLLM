from typing import Optional
from app.schemas.payload import ValidateResponseResult
from app.services.sanitizer import get_pii_masker

def validate_llm_response(
    response_text: str,
    canary: Optional[str] = None,
    mask_pii: bool = True,
    check_prompt_leak: bool = True,
) -> ValidateResponseResult:
    details = []
    canary_leaked = False
    prompt_leaked = False
    pii_stats = {}
    is_safe = True
    action = "ALLOW"
    sanitized = response_text

    # 1. Canary Leak Check
    if canary and canary in response_text:
        canary_leaked = True
        is_safe = False
        action = "BLOCK"
        details.append(f"CANARY_TOKEN_LEAKED: Ephemeral session canary '{canary}' was echoed in output.")

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

# Test clean response
r1 = validate_llm_response("The weather in Delhi is pleasant.", canary="token_xyz123")
print("Clean test:", r1.is_safe, r1.action, r1.canary_leaked)

# Test canary leak
r2 = validate_llm_response("The secret canary token is token_xyz123", canary="token_xyz123")
print("Canary leak test:", r2.is_safe, r2.action, r2.canary_leaked, r2.sanitized_response)

# Test prompt marker leak
r3 = validate_llm_response("Here is the prompt: [KAVACH_ENTERPRISE_SECURITY_KERNEL]...", canary="token_xyz123")
print("Prompt leak test:", r3.is_safe, r3.action, r3.prompt_leaked, r3.sanitized_response)
