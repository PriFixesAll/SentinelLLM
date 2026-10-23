from pathlib import Path

path = Path("app/services/sanitizer.py")
content = path.read_text(encoding="utf-8")

old_block = """        if decision.action is PolicyAction.BLOCK:
            assembled = AssembledContext(
                system=_blocked_system_prompt(),
                trusted_instructions="\\n\\n".join(trusted_parts),
                untrusted_data="",
                messages=[
                    SanitizedMessage(
                        role=MessageRole.SYSTEM,
                        content=_blocked_system_prompt(),
                        source=ContentSource.SYSTEM,
                        trust=TrustLevel.TRUSTED,
                        content_sha256=_sha256(_blocked_system_prompt()),
                    )
                ],
            )
            return SanitizeResponse(
                request_id=request_id,
                decision=decision,
                findings=findings,
                messages=assembled.messages,
                documents=[],
                assembled=assembled,
                canary=canary,
                sanitized_text=primary_clean_text,"""

new_block = """        if decision.action is PolicyAction.BLOCK:
            blocked_refusal = (
                "REQUEST_BLOCKED_BY_KAVACH_GATEWAY: Security policy violation detected. "
                "Malicious exploit generation or unauthorized security bypass request blocked."
            )
            assembled = AssembledContext(
                system=_blocked_system_prompt(),
                trusted_instructions="\\n\\n".join(trusted_parts),
                untrusted_data="",
                messages=[
                    SanitizedMessage(
                        role=MessageRole.SYSTEM,
                        content=_blocked_system_prompt(),
                        source=ContentSource.SYSTEM,
                        trust=TrustLevel.TRUSTED,
                        content_sha256=_sha256(_blocked_system_prompt()),
                    )
                ],
            )
            return SanitizeResponse(
                request_id=request_id,
                decision=decision,
                findings=findings,
                messages=assembled.messages,
                documents=[],
                assembled=assembled,
                canary=canary,
                sanitized_text=blocked_refusal,"""

if "\r\n" in content:
    old_block = old_block.replace("\n", "\r\n")
    new_block = new_block.replace("\n", "\r\n")

assert old_block in content, "old_block not found in sanitizer.py"
content = content.replace(old_block, new_block, 1)

path.write_text(content, encoding="utf-8")
print("Updated sanitizer.py with blocked_refusal successfully!")
