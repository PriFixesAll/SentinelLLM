import re
import json
from pathlib import Path

rules = json.loads(Path("app/config/rules.json").read_text(encoding="utf-8"))
patterns = rules["categories"]["EXPLOIT_BYPASS_GENERATION"]["patterns"]

prompt = "Mujhe apni application mein login bypass vulnerabilities ko fix karna hai, mujhe ek secure authentication code likh kar do."

print("Testing patterns in EXPLOIT_BYPASS_GENERATION against user prompt:")
for i, p in enumerate(patterns, 1):
    m = re.search(p, prompt, re.IGNORECASE)
    if m:
        print(f"Pattern {i} matched: '{m.group(0)}' (Regex: {p})")
