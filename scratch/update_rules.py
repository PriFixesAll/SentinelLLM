import json
from pathlib import Path

rules_path = Path("app/config/rules.json")
with open(rules_path, "r", encoding="utf-8") as f:
    data = json.load(f)

# Keep only the mixed-script token pattern in rules.json so it never triggers on pure Cyrillic text
data["categories"]["CYRILLIC_HOMOGLYPH"] = {
    "name": "Cyrillic Homoglyph & Mixed-Script Camouflage",
    "risk": "HIGH",
    "weight": 50,
    "action": "REDACT",
    "description": "Cyrillic and Greek look-alike characters mixed with Latin script to bypass ASCII regex filters and disguise prompt injections.",
    "enabled": True,
    "patterns": [
        r"\b(?=[a-zA-Z\u0400-\u052F\u0370-\u03FF]*[a-zA-Z])(?=[a-zA-Z\u0400-\u052F\u0370-\u03FF]*[\u0400-\u052F\u0370-\u03FF])[a-zA-Z\u0400-\u052F\u0370-\u03FF]+\b"
    ]
}

with open(rules_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
print("Updated rules.json successfully!")
