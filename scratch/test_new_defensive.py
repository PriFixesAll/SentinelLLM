import re

DEFENSIVE_PATTERNS = [
    # English defensive & mitigation indicators
    r"(?i)\b(?:how\s+to|how\s+can\s+(?:i|we)|ways\s+to|methods?\s+to|best\s+practices?\s+to)\s+(?:prevent|protect|secure|defend|safeguard|harden|mitigate|stop|avoid|test|validate)\b",
    r"(?i)\b(?:prevent|protect|secure|defend|safeguard|harden|mitigate|stop|avoid)\s+(?:against|from)?\s+.*?\b(?:bypass|hack|crack|attack|exploit|injection|breach|vulnerability|tampering)\b",
    r"(?i)\b(?:fix|patch|remediate|resolve|debug|secure)\s+(?:this|the|a|an)?\s+.*?\b(?:vulnerability|bug|flaw|issue|cve|bypass|injection|weakness)\b",
    r"(?i)\b(?:best\s+practices|security\s+guidelines|hardening\s+guide|defensive\s+programming|secure\s+coding|owasp\s+guidelines)\b",
    r"(?i)\b(?:unit\s+test|verify|test\s+case|check|assert)\s+(?:that|if)?\s+.*?\b(?:cannot\s+be\s+bypassed|is\s+secure|fails\s+safely|prevents?|blocks?)\b",
    r"(?i)\b(?:defense\s+against|protection\s+against|measures\s+against|countermeasures?)\b",
    
    # Bidirectional vulnerability remediation (English & Hinglish)
    # e.g. "login bypass vulnerabilities ko fix karna hai" OR "fix login bypass vulnerabilities"
    r"(?i)\b(?:vulnerabilit(?:y|ies)|bugs?|flaws?|issues?|bypass(?:es)?)\b.*?\b(?:fix|patch|resolve|remediate|secure|prevent|mitigate)\b",
    r"(?i)\b(?:fix|patch|resolve|remediate|secure|prevent|mitigate)\b.*?\b(?:vulnerabilit(?:y|ies)|flaws?|bugs?|issues?|bypass(?:es)?)\b",
    r"(?i)\b(?:vulnerabilit(?:y|ies)|bugs?|flaws?|issues?)\s+(?:ko\s+)?(?:fix|patch|resolve|theek|sahi|remediate|hata|dur)\s+(?:karna|karein|karo)\b",
    r"(?i)\b(?:ko\s+)?(?:fix|patch|secure|surakshit)\s+karna\s+(?:hai|chahata|chahta)\b",
    
    # Secure code requests
    r"(?i)\bsecure\s+(?:authentication|auth|login|code|system|implementation|api)\b",
    r"(?i)\b(?:secure|surakshit)\s+(?:authentication\s+)?code\s+(?:likh|bana|generate|de|do|batao|likho)\b",
    
    # Hinglish defensive indicators
    r"(?i)\b(?:se\s+kaise\s+bache[in]?|kaise\s+roka\s+ja\s+sakta\s+hai|surakshit\s+kaise\s+kare[in]?|protect\s+kaise\s+kare[in]?|secure\s+kaise\s+kare[in]?|kaise\s+bache[in]?)\b",
    r"(?i)\b(?:attack|bypass|hack)\s+(?:se\s+bachne|rokne)\s+(?:ka|ki|ke)\s+(?:tarika|tariqa|upay|code|solution|method|tarike)\b",
    r"(?i)\b(?:rokne|bachane|suraksha\s+badhane)\s+(?:ke\s+liye|ka\s+code|ke\s+tarike)\b",
    r"(?i)\b(?:koi\s+hack\s+na\s+kar\s+sake|bypass\s+na\s+ho\s+sake|chori\s+na\s+ho|surakshit\s+code)\b",
    r"(?i)\bbypass\s+hone\s+se\s+kaise\s+(?:bache[in]?|bachaye[in]?|roke[in]?)\b",
]

user_prompt = "Mujhe apni application mein login bypass vulnerabilities ko fix karna hai, mujhe ek secure authentication code likh kar do."

matches = [p for p in DEFENSIVE_PATTERNS if re.search(p, user_prompt)]
print(f"Matched {len(matches)} defensive patterns:")
for m in matches:
    print(" -", m)
