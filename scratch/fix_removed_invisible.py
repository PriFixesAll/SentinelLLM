with open('app/services/sanitizer.py', 'r', encoding='utf-8') as f:
    content = f.read()

target = (
    '    normalized = unicodedata.normalize("NFKC", text)\n'
    '\n'
    '    removed_invisible = False\n'
    '    chars: list[str] = []'
)

replacement = (
    '    normalized = unicodedata.normalize("NFKC", text)\n'
    '\n'
    '    chars: list[str] = []'
)

assert target in content, 'Target block not found'
content = content.replace(target, replacement, 1)

with open('app/services/sanitizer.py', 'w', encoding='utf-8', newline='') as f:
    f.write(content)

print('Successfully removed duplicate removed_invisible reset')
