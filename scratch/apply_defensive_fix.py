import json
from pathlib import Path

# 1. Update rules.json
rules_path = Path("app/config/rules.json")
with open(rules_path, "r", encoding="utf-8") as f:
    data = json.load(f)

# Update pattern 2 to not match if followed by vulnerability, flaw, bug, issue, fix
data["categories"]["EXPLOIT_BYPASS_GENERATION"]["patterns"] = [
    r"\b(?:code|script|payload|tool|tariqa|tarika|method)\s+(?:likh|bana|generate|write|de|batao|do).*?\b(?:bypass|hack|crack|breach|exploit)\b",
    r"\b(?:login|auth|authentication|password|otp|banking|portal|page|account|pin)\s+(?:page\s+|system\s+)?(?:ko\s+)?(?:bypass|hack|crack|breach|phish)(?!\s+(?:vulnerabilit|flaw|bug|issue|defense|protection))\b",
    r"\b(?:bypass|hack|crack|breach)\s+(?:the\s+|a\s+)?(?:login|banking|bank|portal|auth|authentication|password|account|credential)(?!\s+(?:vulnerabilit|flaw|bug|issue))\b",
    r"\b(?:write|generate|give|provide)\s+(?:me\s+)?(?:a\s+)?(?:code|script|program|exploit|payload)\s+(?:to|that\s+can)\s+(?:bypass|crack|hack)\b",
    r"\b(?:banking\s+login|bank\s+account|login\s+page)\b.*?(\bbypass\b)(?!\s+(?:vulnerabilit|flaw|bug|issue|defense))",
    r"\bbypass\s+kar\s+(?:sake|sakta|sakun)\b",
    r"\b(?:hack|crack|bypass)\s+karne\s+(?:ka|ki|ke)\s+(?:code|script|tarika|tariqa|program)\b"
]

with open(rules_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
print("Updated rules.json successfully!")

# 2. Update app/services/intent_analyzer.py
intent_path = Path("app/services/intent_analyzer.py")
intent_content = intent_path.read_text(encoding="utf-8")

old_def_end = '    r"(?i)\\bbypass\\s+hone\\s+se\\s+kaise\\s+(?:bache[in]?|bachaye[in]?|roke[in]?)\\b",\n    r"(?i)\\bsecure\\s+code\\s+likh\\b",\n]'

new_def_end = """    r"(?i)\\bbypass\\s+hone\\s+se\\s+kaise\\s+(?:bache[in]?|bachaye[in]?|roke[in]?)\\b",
    r"(?i)\\bsecure\\s+code\\s+likh\\b",
    
    # Bidirectional vulnerability remediation (English & Hinglish)
    r"(?i)\\b(?:vulnerabilit(?:y|ies)|bugs?|flaws?|issues?|bypass(?:es)?)\\b.*?\\b(?:fix|patch|resolve|remediate|secure|prevent|mitigate)\\b",
    r"(?i)\\b(?:fix|patch|resolve|remediate|secure|prevent|mitigate)\\b.*?\\b(?:vulnerabilit(?:y|ies)|flaws?|bugs?|issues?|bypass(?:es)?)\\b",
    r"(?i)\\b(?:vulnerabilit(?:y|ies)|bugs?|flaws?|issues?)\\s+(?:ko\\s+)?(?:fix|patch|resolve|theek|sahi|remediate|hata|dur)\\s+(?:karna|karein|karo)\\b",
    r"(?i)\\b(?:ko\\s+)?(?:fix|patch|secure|surakshit)\\s+karna\\s+(?:hai|chahata|chahta)\\b",
    
    # Secure code requests
    r"(?i)\\bsecure\\s+(?:authentication|auth|login|code|system|implementation|api)\\b",
    r"(?i)\\b(?:secure|surakshit)\\s+(?:authentication\\s+)?code\\s+(?:likh|bana|generate|de|do|batao|likho)\\b",
]"""

if "\r\n" in intent_content:
    old_def_end = old_def_end.replace("\n", "\r\n")
    new_def_end = new_def_end.replace("\n", "\r\n")

assert old_def_end in intent_content, "old_def_end not found in intent_analyzer.py"
intent_content = intent_content.replace(old_def_end, new_def_end, 1)

intent_path.write_text(intent_content, encoding="utf-8")
print("Updated intent_analyzer.py successfully!")
