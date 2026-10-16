import re

# List of known heuristic / regex patterns for prompt injection and jailbreaks
INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"disregard all prior rules",
    r"you are now (dan|unrestricted)",
    r"developer mode enabled",
    r"system prompt",
    r"reveal your instructions",
    r"bypass safety",
    r"pretend you have no restrictions",
    r"ignore all",  # Naya pattern
    r"system instructions",  # Naya pattern
]


class ThreatClassifier:

  @staticmethod
  def analyze_text(text: str) -> dict:
    """Analyzes text for prompt injection and jailbreak patterns.

    Returns a risk score between 0.0 (safe) and 1.0 (malicious).
    """
    if not text:
      return {"risk_score": 0.0, "matches": [], "action": "PASS"}

    lower_text = text.lower()
    matches = []
    score = 0.0

    for pattern in INJECTION_PATTERNS:
      if re.search(pattern, lower_text):
        matches.append(pattern)
        score += 0.8  # Har match par score 0.8 badhayein taaki turant BLOCK ho

    # Cap the risk score at 1.0
    risk_score = min(score, 1.0)

    # Determine action based on risk score threshold
    if risk_score >= 0.7:
      action = "BLOCK"
    elif risk_score >= 0.3:
      action = "REDACT"
    else:
      action = "PASS"

    return {
        "risk_score": round(risk_score, 2),
        "matches": matches,
        "action": action,
    }