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
    mask_pii: bool = True
    enable_semantic_guard: bool = True
    semantic_threshold: float = Field(default=0.72, ge=0.0, le=1.0)
    force_semantic_check: bool = False
    block_on_critical: bool = True
    preserve_whitespace: bool = True


class SanitizeRequest(BaseModel):
    """Inbound LLM/RAG payload to structurally sanitize before model context assembly."""

    model_config = ConfigDict(extra="forbid")

    request_id: Optional[str] = Field(default=None, max_length=128)
    tenant_id: Optional[str] = Field(default=None, max_length=128)
    application_id: Optional[str] = Field(default=None, max_length=128)
    messages: list[Message] = Field(default_factory=list, max_length=256)
    documents: list[ExternalDocument] = Field(default_factory=list, max_length=64)
    tool_results: list[ToolResult] = Field(default_factory=list, max_length=64)
    options: SanitizeOptions = Field(default_factory=SanitizeOptions)

    # Convenience shortcuts for curl & API ergonomics
    text: Optional[str] = Field(default=None, description="Convenience shortcut: auto-wrapped into a user message")
    prompt: Optional[str] = Field(default=None, description="Convenience shortcut: auto-wrapped into a user message")
    mask_pii: Optional[bool] = Field(default=None, description="Convenience shortcut: syncs to options.mask_pii")
    policy_mode: Optional[PolicyMode] = Field(default=None, description="Convenience shortcut: syncs to options.policy_mode")
    enable_semantic_guard: Optional[bool] = Field(default=None, description="Convenience shortcut: syncs to options.enable_semantic_guard")
    force_semantic_check: Optional[bool] = Field(default=None, description="Convenience shortcut: syncs to options.force_semantic_check")
    semantic_threshold: Optional[float] = Field(default=None, description="Convenience shortcut: syncs to options.semantic_threshold")

    @model_validator(mode="before")
    @classmethod
    def populate_convenience_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            content = data.get("text") or data.get("prompt")
            if content and not data.get("messages"):
                data["messages"] = [{"role": "user", "content": content, "source": "user"}]

            options = data.get("options")
            if options is None:
                options = {}
                data["options"] = options
            if isinstance(options, dict):
                if data.get("mask_pii") is not None and "mask_pii" not in options:
                    options["mask_pii"] = data["mask_pii"]
                if data.get("policy_mode") is not None and "policy_mode" not in options:
                    options["policy_mode"] = data["policy_mode"]
                if data.get("enable_semantic_guard") is not None and "enable_semantic_guard" not in options:
                    options["enable_semantic_guard"] = data["enable_semantic_guard"]
                if data.get("force_semantic_check") is not None and "force_semantic_check" not in options:
                    options["force_semantic_check"] = data["force_semantic_check"]
                if data.get("semantic_threshold") is not None and "semantic_threshold" not in options:
                    options["semantic_threshold"] = data["semantic_threshold"]
        return data

    @model_validator(mode="after")
    def sync_and_validate_channels(self) -> "SanitizeRequest":
        if self.mask_pii is not None:
            self.options.mask_pii = self.mask_pii
        if self.policy_mode is not None:
            self.options.policy_mode = self.policy_mode
        if self.enable_semantic_guard is not None:
            self.options.enable_semantic_guard = self.enable_semantic_guard
        if self.force_semantic_check is not None:
            self.options.force_semantic_check = self.force_semantic_check
        if self.semantic_threshold is not None:
            self.options.semantic_threshold = self.semantic_threshold
        if not self.messages and not self.documents and not self.tool_results:
            raise ValueError("request must include messages, documents, tool_results, or text/prompt")
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
    reasons: list[str] = Field(default_factory=list)
    matches: list[str] = Field(default_factory=list)


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
    sanitized_text: Optional[str] = Field(default=None, description="Direct convenience access to primary sanitized text with PII masked")
    pii_detected: dict[str, int] = Field(default_factory=dict)
    defense_notes: list[str] = Field(default_factory=list)
    diagnostics: dict[str, Any] = Field(default_factory=dict)
