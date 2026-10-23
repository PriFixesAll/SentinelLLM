import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from app.services.sanitizer import detect_cyrillic_homoglyphs

text = "Привет, как твои дела сегодня?"
res = detect_cyrillic_homoglyphs(text)
print("Result for pure Russian:", res)
