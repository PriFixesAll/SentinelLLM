import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from app.services.sanitizer import get_sanitizer
from app.schemas.payload import Message, MessageRole, ContentSource, SanitizeRequest
from app.services.classifier import ThreatClassifier

sanitizer = get_sanitizer()

cat = ThreatClassifier.get_categories().get("CYRILLIC_HOMOGLYPH")
print("CYRILLIC_HOMOGLYPH patterns in ThreatClassifier:", cat.patterns if cat else None)

text = "Привет, как твои дела сегодня?"
msg = Message(role=MessageRole.USER, content=text, source=ContentSource.USER)
res = sanitizer.sanitize(SanitizeRequest(messages=[msg]), request_id="debug_rus")

for f in res.findings:
    print(f"Finding: code={f.code}, title={f.title}, detail={f.detail}")
