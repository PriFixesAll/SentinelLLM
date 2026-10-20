"""Dynamic Threat Classification & External Rule Engine for Kavach-Proxy.

Production-ready rule loader supporting:
- Externalized JSON pattern configurations (`app/config/rules.json`)
- Categorized threat vectors (INSTRUCTION_OVERRIDE, ROLE_IMPERSONATION, SPECIAL_TOKEN_BREAKOUT, EXFIL_LANGUAGE)
- Configurable severity weightings (INFO, LOW, MEDIUM, HIGH, CRITICAL)
- Graceful in-memory fallback on missing or corrupted configuration files
- Dynamic hot-reloading (`ThreatClassifier.reload_rules()`) and zero-day pattern additions
  without server restarts or modifying engine logic.

DEVELOPER EXTENSION GUIDE:
--------------------------
1. Adding a new pattern to an existing category:
   Open `app/config/rules.json`, locate the category (e.g. `INSTRUCTION_OVERRIDE`),
   and append your regex pattern string to the `patterns` array. Then either restart
   the service or call `ThreatClassifier.reload_rules()`.

2. Adding a brand new zero-day threat category:
   In `app/config/rules.json`, add a new key under `categories`:
   ```json
   "ZERO_DAY_VECTOR": {
     "name": "Zero-Day Exploit Name",
     "risk": "HIGH",
     "weight": 45,
     "action": "REDACT",
     "description": "Description of the exploit vector.",
     "enabled": true,
     "patterns": [
       "custom_regex_signature_here"
     ]
   }
   ```
3. Hot-loading programmatically:
   Call `ThreatClassifier.add_pattern("INSTRUCTION_OVERRIDE", r"my_new_jailbreak_regex", save_to_disk=True)`
   or trigger `ThreatClassifier.reload_rules()`.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("kavach.classifier")

# Default path: app/config/rules.json relative to this file
DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "config" / "rules.json"

# In-memory fallback rules in case rules.json is missing or invalid
FALLBACK_RULES: dict[str, Any] = {
    "version": "1.0.0-fallback",
    "description": "Built-in fallback rules for Kavach-Proxy",
    "categories": {
        "SPECIAL_TOKEN_BREAKOUT": {
            "name": "Special Token & Delimiter Breakout",
            "risk": "CRITICAL",
            "weight": 80,
            "action": "BLOCK",
            "description": "Model control tokens, ChatML markers, and delimiter escapes",
            "enabled": True,
            "patterns": [
                r"(<\|/?[a-z0-9._-]{1,40}\|>|\[/?INST\]|<<\s*SYS\s*>>|</?\s*sys\s*>|</?\s*system\s*>|</?\s*im_start\s*>|</?\s*im_end\s*>)",
            ],
        },
        "INSTRUCTION_OVERRIDE": {
            "name": "Instruction Override & Jailbreaks",
            "risk": "HIGH",
            "weight": 45,
            "action": "REDACT",
            "description": "Attempts to overwrite system instructions or disable guardrails",
            "enabled": True,
            "patterns": [
                r"\b(ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)|disregard\s+(the\s+)?(system|developer)\s+(prompt|instructions)|override\s+(the\s+)?(system|safety|guardrails)|you\s+are\s+now\s+(?:a|an|to)|new\s+(system|developer)\s+prompt|from\s+now\s+on\s+(?:you\s+must|ignore)|reveal\s+(your\s+)?(system|hidden|secret)\s+prompt|print\s+(the\s+)?(system|hidden)\s+(prompt|instructions)|disable\s+(your\s+)?(safety|guardrails|filters))\b",
                r"ignore previous instructions",
                r"disregard all prior rules",
                r"you are now (dan|unrestricted)",
                r"developer mode enabled",
                r"system prompt",
                r"reveal your instructions",
                r"bypass safety",
                r"pretend you have no restrictions",
                r"ignore all",
                r"system instructions",
            ],
        },
        "ROLE_IMPERSONATION": {
            "name": "Role Header Impersonation",
            "risk": "HIGH",
            "weight": 45,
            "action": "REDACT",
            "description": "Attempts to spoof conversation role headers in untrusted text",
            "enabled": True,
            "patterns": [
                r"(?:^|\n)\s*(?:system|developer|assistant|tool)\s*:\s+",
            ],
        },
        "EXFIL_LANGUAGE": {
            "name": "Data Exfiltration Directives",
            "risk": "HIGH",
            "weight": 45,
            "action": "REDACT",
            "description": "Directives commanding the model to exfiltrate secrets or prompts",
            "enabled": True,
            "patterns": [
                r"\b(exfiltrat(?:e|ion)|send\s+(this|the)\s+(secret|key|prompt)\s+to|webhook|pastebin|ngrok)\b",
            ],
        },
    },
}


@dataclass
class CompiledRuleCategory:
    """Holds a validated threat category and its compiled regex objects."""

    code: str
    name: str
    risk: str
    weight: int
    action: str
    description: str
    enabled: bool
    patterns: list[str]
    compiled_patterns: list[re.Pattern[str]] = field(default_factory=list)
    combined_pattern: Optional[re.Pattern[str]] = None


class RuleLoader:
    """Loads, validates, and compiles threat patterns from external JSON."""

    def __init__(self, config_path: Optional[Path | str] = None) -> None:
        env_path = os.getenv("KAVACH_RULES_PATH")
        self.config_path: Path = Path(config_path or env_path or DEFAULT_RULES_PATH)
        self.categories: dict[str, CompiledRuleCategory] = {}
        self.load_rules()

    def load_rules(self) -> None:
        """Loads and compiles rules from disk with fallback protection."""
        raw_data = self._read_config_file()
        categories: dict[str, CompiledRuleCategory] = {}

        raw_categories = raw_data.get("categories", {})
        if not raw_categories:
            logger.warning("No categories found in rule config, applying internal fallbacks")
            raw_categories = FALLBACK_RULES["categories"]

        for code, details in raw_categories.items():
            if not isinstance(details, dict):
                continue
            enabled = bool(details.get("enabled", True))
            patterns = [str(p) for p in details.get("patterns", []) if str(p).strip()]
            compiled: list[re.Pattern[str]] = []

            for p in patterns:
                try:
                    compiled.append(re.compile(p, re.IGNORECASE))
                except re.error as err:
                    logger.error("Failed to compile pattern '%s' in category '%s': %s", p, code, err)

            combined_pat: Optional[re.Pattern[str]] = None
            if compiled:
                try:
                    combined_pat = re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)
                except re.error:
                    pass

            categories[code] = CompiledRuleCategory(
                code=code,
                name=details.get("name", code),
                risk=details.get("risk", "HIGH").upper(),
                weight=int(details.get("weight", 45)),
                action=details.get("action", "REDACT").upper(),
                description=details.get("description", ""),
                enabled=enabled,
                patterns=patterns,
                compiled_patterns=compiled,
                combined_pattern=combined_pat,
            )

        self.categories = categories
        logger.info(
            "Loaded %d threat categories (%d active patterns) from %s",
            len(categories),
            sum(len(c.compiled_patterns) for c in categories.values()),
            self.config_path,
        )

    def _read_config_file(self) -> dict[str, Any]:
        """Safely reads the external rules JSON file."""
        if not self.config_path.exists():
            logger.warning("Rules configuration file %s not found. Using fallback rules.", self.config_path)
            return FALLBACK_RULES

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.error("Error reading %s: %s. Reverting to fallback rules.", self.config_path, exc)
            return FALLBACK_RULES

    def append_pattern(
        self,
        category_code: str,
        pattern: str,
        save_to_disk: bool = False,
    ) -> bool:
        """Appends a new pattern to an existing or new category and recompiles."""
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as err:
            logger.error("Invalid regex pattern '%s': %s", pattern, err)
            return False

        if category_code in self.categories:
            cat = self.categories[category_code]
            if pattern not in cat.patterns:
                cat.patterns.append(pattern)
                cat.compiled_patterns.append(compiled)
                try:
                    cat.combined_pattern = re.compile("|".join(f"(?:{p})" for p in cat.patterns), re.IGNORECASE)
                except re.error:
                    pass
        else:
            self.categories[category_code] = CompiledRuleCategory(
                code=category_code,
                name=category_code.replace("_", " ").title(),
                risk="HIGH",
                weight=45,
                action="REDACT",
                description="Dynamically added zero-day rule category",
                enabled=True,
                patterns=[pattern],
                compiled_patterns=[compiled],
                combined_pattern=compiled,
            )

        if save_to_disk:
            self.save_rules_to_disk()

        return True

    def save_rules_to_disk(self) -> bool:
        """Persists currently loaded in-memory rules back to rules.json."""
        try:
            output = {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "version": "1.0.0",
                "description": "Kavach-Proxy threat pattern definitions",
                "categories": {
                    cat.code: {
                        "name": cat.name,
                        "risk": cat.risk,
                        "weight": cat.weight,
                        "action": cat.action,
                        "description": cat.description,
                        "enabled": cat.enabled,
                        "patterns": cat.patterns,
                    }
                    for cat in self.categories.values()
                },
            }
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(output, f, indent=2)
            logger.info("Successfully persisted rules to %s", self.config_path)
            return True
        except Exception as exc:
            logger.error("Failed to save rules to %s: %s", self.config_path, exc)
            return False


# Singleton rule loader instance
_rule_loader = RuleLoader()


def get_rule_loader() -> RuleLoader:
    """Returns the singleton RuleLoader instance."""
    return _rule_loader


class ThreatClassifier:
    """Threat classification gateway evaluating texts against dynamic rule categories."""

    @classmethod
    def get_loader(cls) -> RuleLoader:
        return _rule_loader

    @classmethod
    def reload_rules(cls, config_path: Optional[str | Path] = None) -> bool:
        """Hot-reloads rules from rules.json without service downtime."""
        try:
            if config_path:
                _rule_loader.config_path = Path(config_path)
            _rule_loader.load_rules()
            _sync_module_patterns()
            logger.info("ThreatClassifier successfully hot-reloaded rules.")
            return True
        except Exception as exc:
            logger.error("Failed to hot-reload rules: %s", exc)
            return False

    @classmethod
    def add_pattern(
        cls,
        category: str,
        pattern: str,
        save_to_disk: bool = False,
    ) -> bool:
        """Appends a new pattern dynamically and synchronizes engine."""
        success = _rule_loader.append_pattern(category, pattern, save_to_disk=save_to_disk)
        if success:
            _sync_module_patterns()
        return success

    @classmethod
    def get_category_regex(cls, category: str) -> Optional[re.Pattern[str]]:
        """Returns the compiled combined regex pattern for a category."""
        cat = _rule_loader.categories.get(category)
        if cat and cat.enabled:
            return cat.combined_pattern
        return None

    @classmethod
    def get_categories(cls) -> dict[str, CompiledRuleCategory]:
        """Returns all loaded categories."""
        return _rule_loader.categories

    @staticmethod
    def analyze_text(text: str) -> dict[str, Any]:
        """Analyzes text for prompt injection and jailbreak patterns.

        Maintains backward compatibility while leveraging the dynamic rule engine.
        Returns a dictionary containing risk_score (0.0 to 1.0), matches, action,
        and categorized findings.
        """
        if not text:
            return {
                "risk_score": 0.0,
                "matches": [],
                "action": "PASS",
                "findings": [],
                "categories": [],
            }

        lower_text = text.lower()
        matched_patterns: list[str] = []
        matched_categories: list[str] = []
        findings: list[dict[str, Any]] = []
        total_risk_score = 0.0
        critical_detected = False

        for code, category in _rule_loader.categories.items():
            if not category.enabled:
                continue

            category_matched = False
            for pat_str, compiled_pat in zip(category.patterns, category.compiled_patterns):
                match = compiled_pat.search(text) or compiled_pat.search(lower_text)
                if match:
                    matched_patterns.append(pat_str)
                    category_matched = True
                    # Weighting: Critical matches add 0.8 immediately, High adds 0.45
                    if category.risk == "CRITICAL" or category.weight >= 80:
                        total_risk_score += 0.8
                        critical_detected = True
                    elif category.risk == "HIGH" or category.weight >= 45:
                        total_risk_score += 0.45
                    elif category.risk == "MEDIUM":
                        total_risk_score += 0.25
                    else:
                        total_risk_score += 0.10

            if category_matched:
                matched_categories.append(code)
                findings.append({
                    "category": code,
                    "name": category.name,
                    "risk": category.risk,
                    "action": category.action,
                    "description": category.description,
                })

        risk_score = min(total_risk_score, 1.0)

        # Determine action threshold
        if critical_detected or risk_score >= 0.7:
            action = "BLOCK"
        elif risk_score >= 0.3:
            action = "REDACT"
        else:
            action = "PASS"

        return {
            "risk_score": round(risk_score, 2),
            "matches": matched_patterns,
            "action": action,
            "findings": findings,
            "categories": matched_categories,
        }


def _get_all_pattern_strings() -> list[str]:
    """Flattens all enabled pattern strings across categories for legacy compatibility."""
    patterns: list[str] = []
    for cat in _rule_loader.categories.values():
        if cat.enabled:
            patterns.extend(cat.patterns)
    return patterns


# Module-level legacy list for backward compatibility with existing imports
INJECTION_PATTERNS: list[str] = _get_all_pattern_strings()


def _sync_module_patterns() -> None:
    """Updates module-level INJECTION_PATTERNS when rules are reloaded."""
    global INJECTION_PATTERNS
    INJECTION_PATTERNS = _get_all_pattern_strings()