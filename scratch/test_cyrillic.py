import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import re
import unicodedata

HOMOGLYPH_CONFUSABLES = {
    # Cyrillic Lowercase
    "\u0430": "a",  # Cyrillic small a
    "\u0441": "c",  # Cyrillic small es
    "\u0434": "d",  # Cyrillic small de
    "\u0435": "e",  # Cyrillic small ie
    "\u0451": "e",  # Cyrillic small io
    "\u0456": "i",  # Cyrillic small Byelorussian-Ukrainian i
    "\u0457": "i",  # Cyrillic small yi
    "\u0458": "j",  # Cyrillic small je
    "\u043a": "k",  # Cyrillic small ka
    "\u043e": "o",  # Cyrillic small o
    "\u0440": "p",  # Cyrillic small er
    "\u0455": "s",  # Cyrillic small dze
    "\u0442": "t",  # Cyrillic small te
    "\u0443": "y",  # Cyrillic small u
    "\u0445": "x",  # Cyrillic small ha
    "\u0501": "d",  # Cyrillic small komi de
    "\u051b": "q",  # Cyrillic small qa
    "\u051d": "w",  # Cyrillic small we
    
    # Cyrillic Uppercase
    "\u0410": "A",  # Cyrillic capital A
    "\u0412": "B",  # Cyrillic capital Ve
    "\u0421": "C",  # Cyrillic capital Es
    "\u0415": "E",  # Cyrillic capital Ie
    "\u0401": "E",  # Cyrillic capital Io
    "\u041d": "H",  # Cyrillic capital En
    "\u0406": "I",  # Cyrillic capital Byelorussian-Ukrainian I
    "\u0408": "J",  # Cyrillic capital Je
    "\u041a": "K",  # Cyrillic capital Ka
    "\u041c": "M",  # Cyrillic capital Em
    "\u041e": "O",  # Cyrillic capital O
    "\u0420": "P",  # Cyrillic capital Er
    "\u0405": "S",  # Cyrillic capital Dze
    "\u0422": "T",  # Cyrillic capital Te
    "\u0423": "Y",  # Cyrillic capital U
    "\u0425": "X",  # Cyrillic capital Ha
    "\u04ae": "Y",  # Cyrillic capital straight U
    "\u04c0": "I",  # Cyrillic letter palochka

    # Greek Confusables
    "\u0391": "A",
    "\u0392": "B",
    "\u0395": "E",
    "\u0396": "Z",
    "\u0397": "H",
    "\u0399": "I",
    "\u039a": "K",
    "\u039c": "M",
    "\u039d": "N",
    "\u039f": "O",
    "\u03a1": "P",
    "\u03a4": "T",
    "\u03a5": "Y",
    "\u03a7": "X",
    "\u03bf": "o",
    "\u03b9": "i",
    "\u03bd": "v",
    "\u03b1": "a",
    "\u03c1": "p",
}

HOMOGLYPH_TRANS = str.maketrans(HOMOGLYPH_CONFUSABLES)
CYRILLIC_OR_GREEK_CHAR_RE = re.compile(r"[\u0400-\u052F\u0370-\u03FF]")
MIXED_SCRIPT_WORD_RE = re.compile(r"\b(?=[a-zA-Z\u0400-\u052F\u0370-\u03FF]*[a-zA-Z])(?=[a-zA-Z\u0400-\u052F\u0370-\u03FF]*[\u0400-\u052F\u0370-\u03FF])[a-zA-Z\u0400-\u052F\u0370-\u03FF]+\b")

def detect_cyrillic_homoglyphs(text: str):
    foreign_chars = CYRILLIC_OR_GREEK_CHAR_RE.findall(text)
    if not foreign_chars:
        return None
        
    confusables_found = [ch for ch in foreign_chars if ch in HOMOGLYPH_CONFUSABLES]
    if not confusables_found:
        return None
        
    mixed_words = MIXED_SCRIPT_WORD_RE.findall(text)
    latin_chars = len(re.findall(r"[a-zA-Z]", text))
    foreign_count = len(foreign_chars)
    
    deobfuscated = text.translate(HOMOGLYPH_TRANS)
    
    is_camouflage = False
    reasons = []
    
    if mixed_words:
        is_camouflage = True
        reasons.append(f"Mixed-script tokens: {mixed_words[:5]}")
        
    if confusables_found and latin_chars > foreign_count:
        is_camouflage = True
        reasons.append(f"{len(confusables_found)} confusable characters in predominantly Latin context")
        
    folded_lower = deobfuscated.lower()
    attack_triggers = ["ignore", "bypass", "system", "prompt", "instruction", "developer", "rules", "disregard", "override", "secret", "password", "dan"]
    for kw in attack_triggers:
        if kw in folded_lower and any(ch in HOMOGLYPH_CONFUSABLES for ch in text):
            is_camouflage = True
            reasons.append(f"Camouflaged attack keyword '{kw}'")
            break
            
    return {
        "is_camouflage": is_camouflage,
        "confusables_count": len(confusables_found),
        "confusable_chars": list(set(confusables_found)),
        "mixed_words": mixed_words,
        "deobfuscated": deobfuscated,
        "reasons": reasons
    }

print("Module tested successfully")
