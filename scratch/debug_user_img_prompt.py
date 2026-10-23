import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from app.services.intent_analyzer import IntentAnalyzer

prompt = "Mujhe apni application mein login bypass vulnerabilities ko fix karna hai, mujhe ek secure authentication code likh kar do."
res = IntentAnalyzer.evaluate(prompt)
print("Intent:", res.intent)
print("Status:", res.status)
print("Defensive Score:", res.defensive_score)
print("Offensive Score:", res.offensive_score)
print("Reason:", res.reasoning)
