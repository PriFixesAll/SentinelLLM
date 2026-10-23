"""Context-Aware AI Intent Analysis & False-Positive Mitigation Engine.

Evaluates user prompt semantics to differentiate between:
1. Offensive Intent (Exploit generation, unauthorized bypass, malicious weaponization) -> BLOCK
2. Defensive / Educational Intent (Defensive programming, vulnerability patching, security hardening) -> ALLOW
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


DEFENSIVE_PATTERNS = [
    # English defensive & mitigation indicators
    r"(?i)\b(?:how\s+to|how\s+can\s+(?:i|we)|ways\s+to|methods?\s+to|best\s+practices?\s+to)\s+(?:prevent|protect|secure|defend|safeguard|harden|mitigate|stop|avoid|test|validate)\b",
    r"(?i)\b(?:prevent|protect|secure|defend|safeguard|harden|mitigate|stop|avoid)\s+(?:against|from)?\s+.*?\b(?:bypass|hack|crack|attack|exploit|injection|breach|vulnerability|tampering)\b",
    r"(?i)\b(?:fix|patch|remediate|resolve|debug|secure)\s+(?:this|the|a|an)?\s+.*?\b(?:vulnerability|bug|flaw|issue|cve|bypass|injection|weakness)\b",
    r"(?i)\b(?:best\s+practices|security\s+guidelines|hardening\s+guide|defensive\s+programming|secure\s+coding|owasp\s+guidelines)\b",
    r"(?i)\b(?:unit\s+test|verify|test\s+case|check|assert)\s+(?:that|if)?\s+.*?\b(?:cannot\s+be\s+bypassed|is\s+secure|fails\s+safely|prevents?|blocks?)\b",
    r"(?i)\b(?:defense\s+against|protection\s+against|measures\s+against|countermeasures?)\b",
    
    # Hinglish defensive indicators
    r"(?i)\b(?:se\s+kaise\s+bache[in]?|kaise\s+roka\s+ja\s+sakta\s+hai|surakshit\s+kaise\s+kare[in]?|protect\s+kaise\s+kare[in]?|secure\s+kaise\s+kare[in]?|kaise\s+bache[in]?)\b",
    r"(?i)\b(?:attack|bypass|hack)\s+(?:se\s+bachne|rokne)\s+(?:ka|ki|ke)\s+(?:tarika|tariqa|upay|code|solution|method|tarike)\b",
    r"(?i)\b(?:rokne|bachane|suraksha\s+badhane)\s+(?:ke\s+liye|ka\s+code|ke\s+tarike)\b",
    r"(?i)\b(?:koi\s+hack\s+na\s+kar\s+sake|bypass\s+na\s+ho\s+sake|chori\s+na\s+ho|surakshit\s+code)\b",
    r"(?i)\bbypass\s+hone\s+se\s+kaise\s+(?:bache[in]?|bachaye[in]?|roke[in]?)\b",
    r"(?i)\bsecure\s+code\s+likh\b",
    
    # Bidirectional vulnerability remediation (English & Hinglish)
    r"(?i)\b(?:vulnerabilit(?:y|ies)|bugs?|flaws?|issues?|bypass(?:es)?)\b.*?\b(?:fix|patch|resolve|remediate|secure|prevent|mitigate)\b",
    r"(?i)\b(?:fix|patch|resolve|remediate|secure|prevent|mitigate)\b.*?\b(?:vulnerabilit(?:y|ies)|flaws?|bugs?|issues?|bypass(?:es)?)\b",
    r"(?i)\b(?:vulnerabilit(?:y|ies)|bugs?|flaws?|issues?)\s+(?:ko\s+)?(?:fix|patch|resolve|theek|sahi|remediate|hata|dur)\s+(?:karna|karein|karo)\b",
    r"(?i)\b(?:ko\s+)?(?:fix|patch|secure|surakshit)\s+karna\s+(?:hai|chahata|chahta)\b",
    
    # Secure code requests
    r"(?i)\bsecure\s+(?:authentication|auth|login|code|system|implementation|api)\b",
    r"(?i)\b(?:secure|surakshit)\s+(?:authentication\s+)?code\s+(?:likh|bana|generate|de|do|batao|likho)\b",
]

OFFENSIVE_PATTERNS = [
    # English offensive exploit generation & bypass
    r"(?i)\b(?:write|generate|give|provide|create|code|script|share)\s+(?:me\s+)?(?:an?\s+)?(?:code|script|program|exploit|payload|tool|poc)\s+(?:to|that\s+can|for)?.*?\b(?:bypass|crack|hack|breach|exploit)\b",
    r"(?i)\b(?:how\s+to|how\s+can\s+i|steps?\s+to)\s+(?:bypass|hack|crack|breach|exploit|penetrate|tamper)\s+(?:the|a|someone's)?\s+(?:banking|bank|login|auth|account|password|otp|verification|portal|system)\b",
    r"(?i)\b(?:bypass|hack|crack|breach)\s+(?:the\s+|a\s+)?(?:banking\s+login|bank\s+account|login\s+page|auth\s+portal|otp\s+verification|pin)\b",
    r"(?i)\b(?:exploit|break\s+into|penetrate|infiltrate)\s+(?:the\s+|a\s+)?(?:login|banking|database|system|server)\b",
    r"(?i)\bexploit\s+code\s+to\s+bypass\b",
    
    # Hinglish offensive exploit generation
    r"(?i)\b(?:code|script|payload|tool|tariqa|tarika)\s+(?:likh|bana|generate|write|de|batao|do).*?\b(?:bypass|hack|crack|breach|exploit)\b",
    r"(?i)\b(?:banking|login|auth|password|otp)\s+(?:page\s+)?(?:ko\s+)?(?:bypass|hack|crack)\s+(?:kar\s+sake|karne\s+ka|karna\s+hai|kaise\s+kare[in]?)\b",
    r"(?i)\bbypass\s+kar\s+(?:sake|sakta|sakun)\b",
    r"(?i)\b(?:hack|crack|bypass)\s+karne\s+(?:ka|ki|ke)\s+(?:code|script|tarika|tariqa|program)\b",
]

_COMPILED_DEFENSIVE = [re.compile(p) for p in DEFENSIVE_PATTERNS]
_COMPILED_OFFENSIVE = [re.compile(p) for p in OFFENSIVE_PATTERNS]


@dataclass
class IntentDecision:
    prompt: str
    intent: str  # "DEFENSIVE" | "MALICIOUS" | "NEUTRAL"
    status: str  # "ALLOW" | "BLOCK"
    category: str  # "SAFE_DEVELOPER_QUERY" | "EXPLOIT_ATTEMPT" | "SAFE_GENERAL"
    confidence_score: float
    reasoning: str
    defensive_score: int = 0
    offensive_score: int = 0


class IntentAnalyzer:
    """Analyzes context and intent to eliminate false positives on security queries."""

    @classmethod
    def evaluate(cls, prompt: str) -> IntentDecision:
        defensive_matches = [p.pattern for p in _COMPILED_DEFENSIVE if p.search(prompt)]
        offensive_matches = [p.pattern for p in _COMPILED_OFFENSIVE if p.search(prompt)]

        def_score = len(defensive_matches)
        off_score = len(offensive_matches)

        # Context Analysis Decision Logic:
        # 1. Clear defensive engineering query (prevent, patch, secure, fix, test against attacks)
        if def_score > 0 and (off_score == 0 or re.search(r"(?i)\b(?:prevent|stop|secure|protect|bachne|rokne|fix|patch)\b.*?\b(?:bypass|hack|attack)\b", prompt)):
            return IntentDecision(
                prompt=prompt,
                intent="DEFENSIVE",
                status="ALLOW",
                category="SAFE_DEVELOPER_QUERY",
                confidence_score=0.96,
                reasoning="Defensive engineering context verified: Prompt asks how to protect, secure, or remediate vulnerabilities against attack vectors.",
                defensive_score=def_score,
                offensive_score=off_score,
            )

        # 2. Malicious exploit or unauthorized bypass intent
        if off_score > 0:
            return IntentDecision(
                prompt=prompt,
                intent="MALICIOUS",
                status="BLOCK",
                category="EXPLOIT_ATTEMPT",
                confidence_score=0.95,
                reasoning="Direct request to generate exploit code, crack credentials, or execute unauthorized authentication bypass.",
                defensive_score=def_score,
                offensive_score=off_score,
            )

        # 3. Standard neutral query
        return IntentDecision(
            prompt=prompt,
            intent="NEUTRAL",
            status="ALLOW",
            category="SAFE_GENERAL",
            confidence_score=0.99,
            reasoning="Standard conversational or informational query with zero malicious indicators.",
            defensive_score=0,
            offensive_score=0,
        )


def get_intent_analyzer() -> type[IntentAnalyzer]:
    return IntentAnalyzer
