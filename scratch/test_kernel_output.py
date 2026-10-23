import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from app.services.sanitizer import get_sanitizer
from app.schemas.payload import Message, MessageRole, ContentSource, SanitizeRequest

sanitizer = get_sanitizer()

msg = Message(role=MessageRole.USER, content="Hello, can you help me summarize this document?", source=ContentSource.USER)
req = SanitizeRequest(messages=[msg])
res = sanitizer.sanitize(req, request_id="kernel_test")

print("=== ASSEMBLED SYSTEM PROMPT ===")
print(res.assembled.system)
print("\n=== ASSEMBLED CANARY ===")
print(res.canary)
print("\n=== DECISION ACTION ===")
print(res.decision.action)
