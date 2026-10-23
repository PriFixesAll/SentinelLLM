import re
from pathlib import Path

sanitizer_path = Path("app/services/sanitizer.py")
content = sanitizer_path.read_text(encoding="utf-8")

# 1. Update _HOMOGLYPHS mapping with comprehensive Cyrillic + Greek confusables
old_homoglyphs_block = """# Common homoglyphs used to evade ASCII detectors. Detection-only folding.
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Ζ": "Z",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Υ": "Y",
        "Χ": "X",
        "ο": "o",
        "ι": "i",
        "ν": "v",
        "\\u0430": "a",
    }
)"""

new_homoglyphs_block = """# Comprehensive Unicode Homoglyph & Confusable Dictionary (Cyrillic + Greek to Latin ASCII)
_HOMOGLYPH_CONFUSABLES: dict[str, str] = {
    # Cyrillic Lowercase Confusables
    "а": "a", "\\u0430": "a",
    "с": "c", "\\u0441": "c",
    "е": "e", "\\u0435": "e",
    "ё": "e", "\\u0451": "e",
    "і": "i", "\\u0456": "i",
    "ї": "i", "\\u0457": "i",
    "ј": "j", "\\u0458": "j",
    "к": "k", "\\u043a": "k",
    "о": "o", "\\u043e": "o",
    "р": "p", "\\u0440": "p",
    "ѕ": "s", "\\u0455": "s",
    "т": "t", "\\u0442": "t",
    "у": "y", "\\u0443": "y",
    "х": "x", "\\u0445": "x",
    "ԁ": "d", "\\u0501": "d",
    "ԛ": "q", "\\u051b": "q",
    "ԝ": "w", "\\u051d": "w",

    # Cyrillic Uppercase Confusables
    "А": "A", "\\u0410": "A",
    "В": "B", "\\u0412": "B",
    "С": "C", "\\u0421": "C",
    "Е": "E", "\\u0415": "E",
    "Ё": "E", "\\u0401": "E",
    "Н": "H", "\\u041d": "H",
    "І": "I", "\\u0406": "I",
    "Ј": "J", "\\u0408": "J",
    "К": "K", "\\u041a": "K",
    "М": "M", "\\u041c": "M",
    "О": "O", "\\u041e": "O",
    "Р": "P", "\\u0420": "P",
    "Ѕ": "S", "\\u0405": "S",
    "Т": "T", "\\u0422": "T",
    "У": "Y", "\\u0423": "Y",
    "Х": "X", "\\u0425": "X",
    "Ү": "Y", "\\u04ae": "Y",
    "Ӏ": "I", "\\u04c0": "I",

    # Greek Confusables
    "Α": "A", "\\u0391": "A",
    "Β": "B", "\\u0392": "B",
    "Ε": "E", "\\u0395": "E",
    "Ζ": "Z", "\\u0396": "Z",
    "Η": "H", "\\u0397": "H",
    "Ι": "I", "\\u0399": "I",
    "Κ": "K", "\\u039a": "K",
    "Μ": "M", "\\u039c": "M",
    "Ν": "N", "\\u039d": "N",
    "Ο": "O", "\\u039f": "O",
    "Ρ": "P", "\\u03a1": "P",
    "Τ": "T", "\\u03a4": "T",
    "Υ": "Y", "\\u03a5": "Y",
    "Χ": "X", "\\u03a7": "X",
    "α": "a", "\\u03b1": "a",
    "ο": "o", "\\u03bf": "o",
    "ι": "i", "\\u03b9": "i",
    "ν": "v", "\\u03bd": "v",
    "ρ": "p", "\\u03c1": "p",
}

_HOMOGLYPHS = str.maketrans(_HOMOGLYPH_CONFUSABLES)
_CYRILLIC_OR_GREEK_CHAR_RE = re.compile(r"[\\u0400-\\u052F\\u0370-\\u03FF]")
_MIXED_SCRIPT_WORD_RE = re.compile(
    r"\\b(?=[a-zA-Z\\u0400-\\u052F\\u0370-\\u03FF]*[a-zA-Z])"
    r"(?=[a-zA-Z\\u0400-\\u052F\\u0370-\\u03FF]*[\\u0400-\\u052F\\u0370-\\u03FF])"
    r"[a-zA-Z\\u0400-\\u052F\\u0370-\\u03FF]+\\b"
)
_HOMOGLYPH_ATTACK_KEYWORDS = (
    "ignore", "bypass", "system", "prompt", "instruction",
    "developer", "rules", "disregard", "override", "secret", "password", "dan"
)

def detect_cyrillic_homoglyphs(text: str) -> Optional[dict]:
    \"\"\"Detect Cyrillic homoglyph camouflage and mixed-script evasion attacks.\"\"\"
    foreign_chars = _CYRILLIC_OR_GREEK_CHAR_RE.findall(text)
    if not foreign_chars:
        return None

    confusables_found = [ch for ch in foreign_chars if ch in _HOMOGLYPH_CONFUSABLES]
    if not confusables_found:
        return None

    mixed_words = _MIXED_SCRIPT_WORD_RE.findall(text)
    latin_chars = len(re.findall(r"[a-zA-Z]", text))
    foreign_count = len(foreign_chars)

    deobfuscated = text.translate(_HOMOGLYPHS)
    folded_lower = deobfuscated.lower()

    is_camouflage = False
    reasons: list[str] = []

    if mixed_words:
        is_camouflage = True
        reasons.append(f"Mixed-script tokens: {mixed_words[:5]}")

    if confusables_found and latin_chars > foreign_count:
        is_camouflage = True
        reasons.append(f"{len(confusables_found)} confusable character(s) in Latin text")

    for kw in _HOMOGLYPH_ATTACK_KEYWORDS:
        if kw in folded_lower and any(ch in _HOMOGLYPH_CONFUSABLES for ch in text):
            is_camouflage = True
            reasons.append(f"Camouflaged attack keyword '{kw}'")
            break

    if not is_camouflage:
        return None

    return {
        "is_camouflage": True,
        "confusables_count": len(confusables_found),
        "confusable_chars": list(set(confusables_found)),
        "mixed_words": mixed_words,
        "deobfuscated": deobfuscated,
        "reasons": reasons,
    }"""

old_canonicalize_end = """    if not preserve_whitespace:
        cleaned = re.sub(r"[ \\t]+", " ", cleaned)
        cleaned = re.sub(r"\\n{3,}", "\\n\\n", cleaned)
    return cleaned, findings"""

new_canonicalize_end = """    if not preserve_whitespace:
        cleaned = re.sub(r"[ \\t]+", " ", cleaned)
        cleaned = re.sub(r"\\n{3,}", "\\n\\n", cleaned)

    # Detect and de-obfuscate Cyrillic / mixed-script homoglyph camouflage
    cyr_res = detect_cyrillic_homoglyphs(cleaned)
    if cyr_res:
        findings.append(
            _finding(
                "CYRILLIC_HOMOGLYPH",
                "Cyrillic Homoglyph Camouflage Detected",
                RiskLevel.HIGH,
                channel,
                source,
                f"Detected {cyr_res['confusables_count']} Cyrillic/Greek confusable character(s) ({', '.join(cyr_res['confusable_chars'][:6])}) used to camouflage tokens and evade filters. De-obfuscated to standard ASCII.",
            )
        )
        cleaned = cyr_res["deobfuscated"]

    return cleaned, findings"""

# Handle Windows CRLF vs LF seamlessly
if "\r\n" in content:
    old_homoglyphs_block = old_homoglyphs_block.replace("\n", "\r\n")
    new_homoglyphs_block = new_homoglyphs_block.replace("\n", "\r\n")
    old_canonicalize_end = old_canonicalize_end.replace("\n", "\r\n")
    new_canonicalize_end = new_canonicalize_end.replace("\n", "\r\n")

assert old_homoglyphs_block in content, "old_homoglyphs_block not found in sanitizer.py"
content = content.replace(old_homoglyphs_block, new_homoglyphs_block, 1)

assert old_canonicalize_end in content, "old_canonicalize_end not found in sanitizer.py"
content = content.replace(old_canonicalize_end, new_canonicalize_end, 1)

sanitizer_path.write_text(content, encoding="utf-8")
print("Updated app/services/sanitizer.py successfully!")
