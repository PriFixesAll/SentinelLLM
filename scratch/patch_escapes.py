from pathlib import Path

path = Path("app/services/sanitizer.py")
content = path.read_text(encoding="utf-8")

# 1. Add regexes and decode_unicode_escapes helper
new_helpers = """_UNICODE_ESCAPE_RE = re.compile(r"(?i)\\\\u([0-9a-f]{4})")
_UNICODE_LONG_ESCAPE_RE = re.compile(r"(?i)\\\\U([0-9a-f]{8})")
_HTML_HEX_ESCAPE_RE = re.compile(r"(?i)&#x([0-9a-f]{1,6});")
_HTML_DEC_ESCAPE_RE = re.compile(r"&#([0-9]{1,7});")


def decode_unicode_escapes(text: str) -> tuple[str, int]:
    escapes_count = 0

    def replace_u(match: re.Match[str]) -> str:
        nonlocal escapes_count
        try:
            ch = chr(int(match.group(1), 16))
            escapes_count += 1
            return ch
        except (ValueError, OverflowError):
            return match.group(0)

    def replace_dec(match: re.Match[str]) -> str:
        nonlocal escapes_count
        try:
            ch = chr(int(match.group(1), 10))
            escapes_count += 1
            return ch
        except (ValueError, OverflowError):
            return match.group(0)

    text = _UNICODE_ESCAPE_RE.sub(replace_u, text)
    text = _UNICODE_LONG_ESCAPE_RE.sub(replace_u, text)
    text = _HTML_HEX_ESCAPE_RE.sub(replace_u, text)
    text = _HTML_DEC_ESCAPE_RE.sub(replace_dec, text)
    return text, escapes_count
"""

target_pos = "def canonicalize("
assert target_pos in content, "def canonicalize( not found"
content = content.replace(target_pos, new_helpers + "\n\n" + target_pos, 1)

# 2. Add decode_unicode_escapes call inside canonicalize()
old_canonicalize_start = """    if "\\x00" in text:
        findings.append(
            _finding("NULL_BYTES", "Null bytes stripped", RiskLevel.MEDIUM, channel, source, "C0 NUL removed.")
        )
        text = _NULL_RE.sub("", text)"""

new_canonicalize_start = """    # Decode literal unicode / hex / HTML escape sequences so steganography and homoglyphs are exposed
    decoded_text, escapes_count = decode_unicode_escapes(text)
    if escapes_count > 0:
        text = decoded_text

    if "\\x00" in text:
        findings.append(
            _finding("NULL_BYTES", "Null bytes stripped", RiskLevel.MEDIUM, channel, source, "C0 NUL removed.")
        )
        text = _NULL_RE.sub("", text)"""

if "\r\n" in content:
    old_canonicalize_start = old_canonicalize_start.replace("\n", "\r\n")
    new_canonicalize_start = new_canonicalize_start.replace("\n", "\r\n")

assert old_canonicalize_start in content, "old_canonicalize_start not found in sanitizer.py"
content = content.replace(old_canonicalize_start, new_canonicalize_start, 1)

path.write_text(content, encoding="utf-8")
print("Updated sanitizer.py with decode_unicode_escapes successfully!")
