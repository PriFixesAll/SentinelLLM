"""Kavach-Proxy FastAPI service: structural sanitization gateway for LLM traffic."""

from __future__ import annotations
from app.services.classifier import ThreatClassifier

import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

from app import __version__
from app.schemas.payload import PolicyAction, SanitizeRequest, SanitizeResponse
from app.services.sanitizer import get_pii_masker, get_sanitizer
from app.services.semantic_guard import get_semantic_guard

logger = logging.getLogger("kavach")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KAVACH_", extra="ignore")

    service_name: str = "kavach-proxy"
    environment: str = "production"
    cors_allow_origins: str = ""
    max_body_bytes: int = 2_000_000
    trusted_hosts: str = ""


settings = Settings()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logger.info("Kavach-Proxy %s starting (%s)", __version__, settings.environment)
    get_sanitizer()
    get_pii_masker()
    get_semantic_guard()
    yield
    logger.info("Kavach-Proxy shutdown")


app = FastAPI(
    title="Kavach-Proxy",
    description=(
        "Enterprise security proxy that structurally sanitizes LLM, RAG, and tool "
        "payloads to defend against indirect prompt injection. Untrusted channels "
        "(user text, retrieved documents, tool results, web, email) are isolated "
        "from trusted system/developer instructions."
    ),
    version=__version__,
    default_response_class=JSONResponse,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

_origins = [o.strip() for o in settings.cors_allow_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins or ["http://127.0.0.1", "http://localhost"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-Tenant-ID"],
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    started = time.perf_counter()
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = request_id

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.max_body_bytes:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={
                        "error": "payload_too_large",
                        "detail": f"Body exceeds {settings.max_body_bytes} bytes",
                        "request_id": request_id,
                    },
                )
        except ValueError:
            pass

    try:
        response: Response = await call_next(request)
    except Exception:
        logger.exception("unhandled_error request_id=%s path=%s", request_id, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "internal_error", "request_id": request_id},
        )

    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Kavach-Version"] = __version__
    logger.info(
        "request method=%s path=%s status=%s duration_ms=%s request_id=%s",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
        request_id,
    )
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "validation_error",
            "request_id": request_id,
            "detail": jsonable_encoder(exc.errors()),
        },
    )


@app.exception_handler(ValidationError)
async def pydantic_handler(request: Request, exc: ValidationError):
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "validation_error",
            "request_id": request_id,
            "detail": jsonable_encoder(exc.errors()),
        },
    )


@app.get("/health", tags=["ops"])
async def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.service_name, "version": __version__}


@app.get("/ready", tags=["ops"])
async def ready() -> dict[str, str]:
    get_sanitizer()
    get_pii_masker()
    get_semantic_guard()
    return {"status": "ready"}


@app.post(
    "/v1/sanitize",
    response_model=SanitizeResponse,
    tags=["sanitize"],
    summary="Structurally sanitize an LLM/RAG payload",
)
async def sanitize(payload: SanitizeRequest, request: Request) -> SanitizeResponse:
    request_id = payload.request_id or request.state.request_id
    try:
        result = get_sanitizer().sanitize(payload, request_id=request_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if result.pii_detected:
        logger.info(
            "pii_redacted request_id=%s tenant=%s entities=%s",
            request_id,
            payload.tenant_id,
            result.pii_detected,
        )

    if result.decision.action is PolicyAction.BLOCK:
        logger.warning(
            "blocked request_id=%s tenant=%s score=%s",
            request_id,
            payload.tenant_id,
            result.decision.score,
        )
    return result


@app.post(
    "/v1/mask-pii",
    tags=["sanitize"],
    summary="Directly mask PII entities in an arbitrary text payload",
)
async def mask_pii_endpoint(payload: dict[str, str], request: Request) -> dict[str, Any]:
    text = payload.get("text", "")
    sanitized_text, stats = get_pii_masker().mask(text)
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    if stats:
        logger.info("pii_redacted request_id=%s entities=%s", request_id, stats)
    return {
        "request_id": request_id,
        "sanitized_text": sanitized_text,
        "pii_detected": stats,
    }


@app.post(
    "/v1/check-semantic",
    tags=["sanitize"],
    summary="Directly evaluate semantic embedding similarity against attack baselines",
)
async def check_semantic_endpoint(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    text = payload.get("text", "")
    threshold = payload.get("threshold")
    guard = get_semantic_guard()
    is_jb, score, matched = guard.check_similarity(text, threshold=threshold)
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    return {
        "request_id": request_id,
        "text": text,
        "is_jailbreak": is_jb,
        "similarity_score": score,
        "matched_baseline": matched,
        "backend": guard.backend,
        "threshold": threshold or guard.similarity_threshold,
    }


@app.get("/", tags=["ops"])
async def root() -> dict[str, Any]:
    return {
        "service": "Kavach-Proxy",
        "version": __version__,
        "docs": "/docs",
        "sanitize": "POST /v1/sanitize",
    }
