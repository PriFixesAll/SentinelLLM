"""Request and response contracts for Kavach-Proxy sanitization."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class TrustLevel(str, Enum):
    """Provenance trust of a content channel."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class ContentSource(str, Enum):
    """Where the bytes originated. All non-system sources are untrusted by default."""

    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    RETRIEVED_DOCUMENT = "retrieved_document"
    TOOL_RESULT = "tool_result"
    WEB = "web"
    EMAIL = "email"
    FILE = "file"
    CONVERSATION_HISTORY = "conversation_history"


class MessageRole(str, Enum):
    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class SpotlightMode(str, Enum):
    """Microsoft Spotlighting-style provenance transforms for untrusted text."""

    DELIMIT = "delimit"
    DATAMARK = "datamark"
    ENCODE = "encode"
    COMBINED = "combined"


class PolicyMode(str, Enum):
    """observe records findings; enforce may wrap, redact, or block."""

    OBSERVE = "observe"
    ENFORCE = "enforce"


class RiskLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyAction(str, Enum):
    ALLOW = "allow"
    WRAP = "wrap"
    REDACT = "redact"
    BLOCK = "block"


_UNTRUSTED_SOURCES = {
    ContentSource.USER,
    ContentSource.RETRIEVED_DOCUMENT,
    ContentSource.TOOL_RESULT,
    ContentSource.WEB,
    ContentSource.EMAIL,
    ContentSource.FILE,
    ContentSource.CONVERSATION_HISTORY,
}


class Message(BaseModel):
    """One chat message. Untrusted roles must never be promoted to system."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    role: MessageRole
    content: str = Field(..., min_length=0, max_length=512_000)
    source: ContentSource = ContentSource.USER
    name: Optional[str] = Field(default=None, max_length=128)
    tool_call_id: Optional[str] = Field(default=None, max_length=128)
    metadata: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def bind_trust_to_role(self) -> "Message":
        if self.role in {MessageRole.SYSTEM, MessageRole.DEVELOPER}:
            if self.source not in {ContentSource.SYSTEM, ContentSource.DEVELOPER}:
                raise ValueError(
                    "system/developer roles may only carry SYSTEM or DEVELOPER sources"
                )
        if self.role == MessageRole.TOOL and self.source != ContentSource.TOOL_RESULT:
            raise ValueError("tool role must use source=tool_result")
        return self


class ExternalDocument(BaseModel):
    """RAG chunk, attachment, email body, or fetched page — always untrusted."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=256)
    source: ContentSource = ContentSource.RETRIEVED_DOCUMENT
    title: Optional[str] = Field(default=None, max_length=512)
    uri: Optional[str] = Field(default=None, max_length=2048)
    mime_type: Optional[str] = Field(default=None, max_length=128)
    content: str = Field(..., min_length=0, max_length=1_048_576)
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("source")
    @classmethod
    def reject_trusted_document_source(cls, value: ContentSource) -> ContentSource:
        if value in {ContentSource.SYSTEM, ContentSource.DEVELOPER}:
            raise ValueError("external documents cannot be marked as trusted system content")
        return value


class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_call_id: str = Field(..., min_length=1, max_length=128)
    name: str = Field(..., min_length=1, max_length=128)
    content: str = Field(..., min_length=0, max_length=512_000)
    is_error: bool = False


class SanitizeOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_mode: PolicyMode = PolicyMode.ENFORCE
    spotlight: SpotlightMode = SpotlightMode.COMBINED
    datamark_token: str = Field(default="ˆ", min_length=1, max_length=8)
    max_untrusted_chars: int = Field(default=200_000, ge=256, le=1_048_576)
    include_canary: bool = True
    redact_instruction_spans: bool = True
    block_on_critical: bool = True
    preserve_whitespace: bool = True


class SanitizeRequest(BaseModel):
    """Inbound LLM/RAG payload to structurally sanitize before model context assembly."""

    model_config = ConfigDict(extra="forbid")

    request_id: Optional[str] = Field(default=None, max_length=128)
    tenant_id: Optional[str] = Field(default=None, max_length=128)
    application_id: Optional[str] = Field(default=None, max_length=128)
    messages: list[Message] = Field(..., min_length=1, max_length=256)
    documents: list[ExternalDocument] = Field(default_factory=list, max_length=64)
    tool_results: list[ToolResult] = Field(default_factory=list, max_length=64)
    options: SanitizeOptions = Field(default_factory=SanitizeOptions)

    @model_validator(mode="after")
    def require_at_least_one_content_channel(self) -> "SanitizeRequest":
        if not self.messages and not self.documents and not self.tool_results:
            raise ValueError("request must include messages, documents, or tool_results")
        return self


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    title: str
    risk: RiskLevel
    channel: str
    source: ContentSource
    detail: str
    span_preview: Optional[str] = None


class SanitizedMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: MessageRole
    content: str
    source: ContentSource
    trust: TrustLevel
    name: Optional[str] = None
    tool_call_id: Optional[str] = None
    envelope_id: Optional[str] = None
    content_sha256: str


class SanitizedDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    source: ContentSource
    trust: TrustLevel = TrustLevel.UNTRUSTED
    title: Optional[str] = None
    uri: Optional[str] = None
    content: str
    envelope_id: str
    content_sha256: str


class AssembledContext(BaseModel):
    """Ready-to-send structured channels. Untrusted data is never merged into system."""

    system: str
    trusted_instructions: str
    untrusted_data: str
    messages: list[SanitizedMessage]


class PolicyDecision(BaseModel):
    action: PolicyAction
    mode: PolicyMode
    score: int = Field(..., ge=0, le=100)
    reason: str


class SanitizeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    decision: PolicyDecision
    findings: list[Finding]
    messages: list[SanitizedMessage]
    documents: list[SanitizedDocument]
    assembled: AssembledContext
    canary: Optional[str] = None
    defense_notes: list[str] = Field(default_factory=list)
    diagnostics: dict[str, Any] = Field(default_factory=dict)
