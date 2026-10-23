from pathlib import Path

path = Path("app/main.py")
content = path.read_text(encoding="utf-8")

# 1. Update imports
old_imp1 = "from app.schemas.payload import PolicyAction, SanitizeRequest, SanitizeResponse"
new_imp1 = "from app.schemas.payload import PolicyAction, SanitizeRequest, SanitizeResponse, ValidateResponseRequest, ValidateResponseResult"

old_imp2 = "from app.services.sanitizer import get_pii_masker, get_sanitizer"
new_imp2 = "from app.services.sanitizer import get_pii_masker, get_sanitizer, validate_llm_response"

if "\r\n" in content:
    old_imp1 = old_imp1.replace("\n", "\r\n")
    new_imp1 = new_imp1.replace("\n", "\r\n")
    old_imp2 = old_imp2.replace("\n", "\r\n")
    new_imp2 = new_imp2.replace("\n", "\r\n")

assert old_imp1 in content, "old_imp1 not found"
assert old_imp2 in content, "old_imp2 not found"
content = content.replace(old_imp1, new_imp1, 1)
content = content.replace(old_imp2, new_imp2, 1)

# 2. Add endpoint before @app.get("/")
old_target = '@app.get("/", tags=["ops"])'

endpoint_code = """@app.post(
    "/v1/validate-response",
    response_model=ValidateResponseResult,
    tags=["validate"],
    summary="Validate outbound LLM response against Canary leakage, prompt extraction, and PII",
)
async def validate_response_endpoint(payload: ValidateResponseRequest, request: Request) -> ValidateResponseResult:
    result = validate_llm_response(
        response_text=payload.response_text,
        canary=payload.canary,
        mask_pii=payload.mask_pii,
        check_prompt_leak=payload.check_prompt_leak,
    )
    if not result.is_safe:
        logger.warning(
            "outbound_leak_detected canary_leaked=%s prompt_leaked=%s details=%s",
            result.canary_leaked,
            result.prompt_leaked,
            result.details,
        )
    return result


"""

if "\r\n" in content:
    old_target = old_target.replace("\n", "\r\n")
    endpoint_code = endpoint_code.replace("\n", "\r\n")

assert old_target in content, "old_target not found"
content = content.replace(old_target, endpoint_code + old_target, 1)

path.write_text(content, encoding="utf-8")
print("Added /v1/validate-response endpoint to app/main.py successfully!")
