from pathlib import Path

path = Path("app/services/sanitizer.py")
content = path.read_text(encoding="utf-8")

old_code = """        for pattern_re in category.compiled_patterns:
            if code == "ROLE_IMPERSONATION":
                if pattern_re.search(cleaned):
                    matched = True
                    matching_pat = pattern_re
                    break
            else:
                if pattern_re.search(folded) or pattern_re.search(cleaned):
                    matched = True
                    matching_pat = pattern_re
                    break"""

new_code = """        for pattern_re in category.compiled_patterns:
            if code in {"ROLE_IMPERSONATION", "CYRILLIC_HOMOGLYPH"}:
                if pattern_re.search(cleaned):
                    matched = True
                    matching_pat = pattern_re
                    break
            else:
                if pattern_re.search(folded) or pattern_re.search(cleaned):
                    matched = True
                    matching_pat = pattern_re
                    break"""

if "\r\n" in content:
    old_code = old_code.replace("\n", "\r\n")
    new_code = new_code.replace("\n", "\r\n")

assert old_code in content, "old_code not found in sanitizer.py"
content = content.replace(old_code, new_code, 1)

path.write_text(content, encoding="utf-8")
print("Updated detect_injections in sanitizer.py successfully!")
