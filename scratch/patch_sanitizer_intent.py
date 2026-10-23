from pathlib import Path

path = Path("app/services/sanitizer.py")
content = path.read_text(encoding="utf-8")

# 1. Update imports
old_imp = """from app.services.classifier import ThreatClassifier
from app.services.semantic_guard import get_semantic_guard"""

new_imp = """from app.services.classifier import ThreatClassifier
from app.services.semantic_guard import get_semantic_guard
from app.services.intent_analyzer import IntentAnalyzer"""

if "\r\n" in content:
    old_imp = old_imp.replace("\n", "\r\n")
    new_imp = new_imp.replace("\n", "\r\n")

assert old_imp in content, "old_imp not found"
content = content.replace(old_imp, new_imp, 1)

# 2. Add intent evaluation logic before decision = self._decide
old_decide = "        decision = self._decide(findings, options)"

intent_block = """        intent_decision = None
        if primary_clean_text:
            intent_decision = IntentAnalyzer.evaluate(primary_clean_text)
            if intent_decision.intent == "DEFENSIVE":
                # False-Positive Mitigation:
                # If intent is verified defensive/engineering, suppress exploit/bypass findings
                suppressed_codes = {"EXPLOIT_BYPASS_GENERATION", "INSTRUCTION_OVERRIDE", "SEMANTIC_JAILBREAK"}
                original_len = len(findings)
                findings = [f for f in findings if f.code not in suppressed_codes]
                if len(findings) < original_len or intent_decision.defensive_score > 0:
                    findings.append(
                        Finding(
                            code="DEFENSIVE_ENGINEERING_INTENT",
                            title="Defensive Engineering Context Verified",
                            risk=RiskLevel.INFO,
                            channel="messages[0].user",
                            source=ContentSource.USER,
                            detail=intent_decision.reasoning,
                        )
                    )
            elif intent_decision.intent == "MALICIOUS" and not any(f.risk is RiskLevel.CRITICAL for f in findings):
                findings.append(
                    Finding(
                        code="EXPLOIT_BYPASS_GENERATION",
                        title="Malicious Exploit Intent Detected",
                        risk=RiskLevel.CRITICAL,
                        channel="messages[0].user",
                        source=ContentSource.USER,
                        detail=intent_decision.reasoning,
                    )
                )

        decision = self._decide(findings, options)"""

if "\r\n" in content:
    old_decide = old_decide.replace("\n", "\r\n")
    intent_block = intent_block.replace("\n", "\r\n")

assert old_decide in content, "old_decide not found"
content = content.replace(old_decide, intent_block, 1)

path.write_text(content, encoding="utf-8")
print("Updated sanitizer.py with Intent Analysis & False-Positive Mitigation successfully!")
