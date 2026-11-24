"""AgentGrid - signed identity, discovery and handoff layer for AI agents.

No wallet, no escrow, no in-app payments. Developers pay externally and an
operator grants access with an admin key plus TOTP.
"""
from __future__ import annotations

import base64
import binascii
import calendar
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import struct
import time
import uuid
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from welcome_email import send_verification_email, send_welcome_email
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import Boolean, Column, Integer, String, Text, func, text, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import StaticPool

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agentgrid")

APP_ENV = os.environ.get("AGENTGRID_APP_ENV", "development").lower()
PUBLIC_BASE_URL = os.environ.get("AGENTGRID_PUBLIC_URL", "https://agentgrid-pied.vercel.app").rstrip("/")
DATABASE_URL = (
    os.environ.get("AGENTGRID_DATABASE_URL")
    or os.environ.get("DATABASE_URL")
    or "sqlite+aiosqlite:///./agentgrid.db"
)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+asyncpg://" + DATABASE_URL[len("postgres://"):]
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+asyncpg://" + DATABASE_URL[len("postgresql://"):]

if DATABASE_URL.startswith("postgresql+asyncpg://"):
    # asyncpg uses `ssl`, not libpq's `sslmode`, and does not accept
    # `channel_binding` as a connect kwarg. Normalize provider URLs here so
    # pasted Neon/Postgres strings work without manual editing.
    parts = urlsplit(DATABASE_URL)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    if "sslmode" in query:
        query.setdefault("ssl", query.pop("sslmode"))
    query.pop("channel_binding", None)
    DATABASE_URL = urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
    )

_engine_kwargs: dict[str, Any] = {}
if DATABASE_URL.startswith("sqlite"):
    _engine_kwargs["connect_args"] = {"check_same_thread": False}
if ":memory:" in DATABASE_URL:
    _engine_kwargs["poolclass"] = StaticPool

engine = create_async_engine(DATABASE_URL, echo=False, **_engine_kwargs)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()

ADMIN_KEY = os.environ.get("AGENTGRID_ADMIN_KEY", "")
ADMIN_MFA_SECRET = os.environ.get("AGENTGRID_ADMIN_MFA_SECRET", "")
OPS_LITE_KEY = os.environ.get("AGENTGRID_OPS_LITE_KEY", "")
OPS_LITE_CATCH = os.environ.get("AGENTGRID_OPS_LITE_CATCH", "")
OPS_LITE_FRAME_ANCESTORS = (
    os.environ.get("AGENTGRID_OPS_LITE_FRAME_ANCESTORS", "'self'").strip() or "'self'"
)

TIER_LIMITS = {
    "free": {"agents": 5, "handoffs": 100},
    "plus": {"agents": 100, "handoffs": 10_000},
    "pro": {"agents": 1_000, "handoffs": 100_000},
    "enterprise": {"agents": 10_000, "handoffs": 1_000_000},
}
# Client IDs created by our own tests/operators. Excluded from the public
# "pulse" totals so smoke tests do not inflate launch numbers.
OPERATOR_TEST_PREFIXES = (
    "smoke_",
    "livetest_",
    "synbill_",
    "adminlive_",
    "emailcheck_",
    "human_",
)
# Small, deliberately conservative list. A match is a signal for the operator
# console, never a block: real users can own addresses on these domains.
DISPOSABLE_EMAIL_DOMAINS = frozenset(
    {
        "10minutemail.com",
        "dispostable.com",
        "fakeinbox.com",
        "getairmail.com",
        "guerrillamail.com",
        "mailinator.com",
        "mailnull.com",
        "mintemail.com",
        "mytrashmail.com",
        "sharklasers.com",
        "spam4.me",
        "temp-mail.org",
        "tempmail.com",
        "throwawaymail.com",
        "trashmail.com",
        "yopmail.com",
    }
)
TIER_PRICES_USD = {
    "free": 0,
    "plus": 20,
    "pro": 150,
    "enterprise": "custom ($2,500-$5,000)",
}
TIER_BASE_MICRODOLLARS = {
    "free": 0,
    "plus": 20_000_000,
    "pro": 150_000_000,
    "enterprise": None,
}
OVERAGE_HANDOFF_MICRODOLLARS = 1_000  # $1 per 1,000 extra handoffs
OVERAGE_AGENT_DAY_MICRODOLLARS = 100_000  # $0.10 per extra agent per day
HARD_CAP_MULTIPLIER = 3
API_KEY_PATTERN = re.compile(r"^agk_[A-Za-z0-9_-]{32,}$")
HEX64_PATTERN = re.compile(r"^[a-f0-9]{64}$")
HANDOFF_ID_PATTERN = re.compile(r"^h_[a-f0-9]{32}$")
ORDER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,128}$")
URL_PATTERN = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)

MAX_BODY_BYTES = 64_000
MAX_SCOPE_BYTES = 8_000
MAX_CLOCK_SKEW_SECONDS = 300
try:
    RATE_LIMIT_PER_MIN = int(os.environ.get("AGENTGRID_RATE_LIMIT_PER_MIN", "120"))
except ValueError:
    RATE_LIMIT_PER_MIN = 120
_rate_bucket: dict[str, list[float]] = {}
SKIP_SCHEMA_ON_STARTUP = os.environ.get(
    "AGENTGRID_SKIP_SCHEMA_ON_STARTUP", ""
).strip().lower() in {"1", "true", "yes", "on"}
SENSITIVE_KEY_FRAGMENTS = ("key", "token", "password", "secret", "authorization", "cookie", "credential")


def _safe_audit_metadata(metadata: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not metadata:
        return {}
    cleaned: dict[str, Any] = {}
    for name, value in metadata.items():
        normalized = str(name).lower().replace("-", "_")
        if any(fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS):
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            cleaned[str(name)[:64]] = value
    return cleaned


# ---------------------------------------------------------------------------
# Encoding + signing helpers
# ---------------------------------------------------------------------------
def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > 200:
        raise ValueError("Invalid base64url value")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _load_platform_key() -> Ed25519PrivateKey:
    raw = os.environ.get("AGENTGRID_SIGNING_KEY_B64", "").strip()
    if raw:
        try:
            key_bytes = _b64d(raw)
        except (ValueError, binascii.Error) as exc:
            raise RuntimeError("AGENTGRID_SIGNING_KEY_B64 is not valid base64url.") from exc
        if len(key_bytes) != 32:
            raise RuntimeError("AGENTGRID_SIGNING_KEY_B64 must decode to 32 bytes.")
        return Ed25519PrivateKey.from_private_bytes(key_bytes)
    if APP_ENV == "production":
        raise RuntimeError("AGENTGRID_SIGNING_KEY_B64 is required in production.")
    logger.warning("No AGENTGRID_SIGNING_KEY_B64 set; using an ephemeral dev signing key.")
    return Ed25519PrivateKey.generate()


def _public_b64(key: Ed25519PrivateKey) -> str:
    return _b64e(
        key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )


def _load_previous_key() -> Optional[Ed25519PrivateKey]:
    raw = os.environ.get("AGENTGRID_PREVIOUS_SIGNING_KEY_B64", "").strip()
    if not raw:
        return None
    try:
        key_bytes = _b64d(raw)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError("AGENTGRID_PREVIOUS_SIGNING_KEY_B64 is not valid base64url.") from exc
    if len(key_bytes) != 32:
        raise RuntimeError("AGENTGRID_PREVIOUS_SIGNING_KEY_B64 must decode to 32 bytes.")
    return Ed25519PrivateKey.from_private_bytes(key_bytes)


PLATFORM_PRIVATE = _load_platform_key()
PLATFORM_PUBLIC_B64 = _public_b64(PLATFORM_PRIVATE)
PREVIOUS_PLATFORM_PRIVATE = _load_previous_key()
PLATFORM_VERIFICATION_KEYS = [PLATFORM_PRIVATE, PREVIOUS_PLATFORM_PRIVATE] if PREVIOUS_PLATFORM_PRIVATE else [PLATFORM_PRIVATE]


def sign_platform(payload: dict[str, Any]) -> str:
    return _b64e(PLATFORM_PRIVATE.sign(canonical_bytes(payload)))


def verify_platform(payload: dict[str, Any], signature_b64: str) -> bool:
    try:
        message = canonical_bytes(payload)
        signature = _b64d(signature_b64)
    except (ValueError, TypeError):
        return False
    for key in PLATFORM_VERIFICATION_KEYS:
        try:
            _public_b64(key)
            Ed25519PublicKey.from_public_bytes(_b64d(_public_b64(key))).verify(signature, message)
            return True
        except (InvalidSignature, ValueError, TypeError, binascii.Error):
            continue
    return False


def verify_agent_signature(payload: dict[str, Any], signature_b64: str, public_b64: str) -> bool:
    try:
        public = Ed25519PublicKey.from_public_bytes(_b64d(public_b64))
        public.verify(_b64d(signature_b64), canonical_bytes(payload))
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_date(value: Optional[str]) -> Optional[date]:
    if not value:
        return None
    return date.fromisoformat(value[:10])


def _next_cycle_date(value: date) -> date:
    """Same day next month; clamps Jan 31 -> Feb 28/29."""
    year = value.year + (1 if value.month == 12 else 0)
    month = 1 if value.month == 12 else value.month + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


def _format_usd(microdollars: int) -> str:
    return f"{microdollars / 1_000_000:.4f}".rstrip("0").rstrip(".")


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _mask_email(email: Optional[str]) -> Optional[str]:
    if not email or "@" not in email:
        return email
    local, domain = email.rsplit("@", 1)
    return f"{(local[0] if local else '')}***@{domain}"


def _email_is_disposable(email: Optional[str]) -> bool:
    if not email or "@" not in email:
        return False
    return email.rsplit("@", 1)[1].lower() in DISPOSABLE_EMAIL_DOMAINS


def _valid_recent_timestamp(value: str) -> bool:
    try:
        parsed = _parse_iso(value)
    except (ValueError, TypeError):
        return False
    if parsed is None or parsed.tzinfo is None:
        return False
    return abs((datetime.now(timezone.utc) - parsed).total_seconds()) <= MAX_CLOCK_SKEW_SECONDS


def _validate_scope(scope: dict[str, Any]) -> bool:
    try:
        encoded = canonical_bytes(scope)
    except (ValueError, TypeError):
        return False
    if len(encoded) > MAX_SCOPE_BYTES:
        return False
    return isinstance(scope, dict) and all(isinstance(key, str) for key in scope)


def _totp_code(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 1_000_000:06d}"


def _verify_totp(secret_b32: str, supplied: str, at_time: Optional[int] = None) -> bool:
    if not re.fullmatch(r"\d{6}", supplied or ""):
        return False
    try:
        counter = int((time.time() if at_time is None else at_time) // 30)
        return any(
            hmac.compare_digest(_totp_code(secret_b32, counter + offset), supplied)
            for offset in (-1, 0, 1)
        )
    except (ValueError, TypeError, binascii.Error):
        return False


# ---------------------------------------------------------------------------
# Database models
# ---------------------------------------------------------------------------
class ClientModel(Base):
    __tablename__ = "clients"

    client_id = Column(String(100), primary_key=True)
    api_key_hash = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(320), nullable=True, index=True)
    email_verified = Column(Boolean, nullable=False, default=True)
    verification_code_hash = Column(String(64), nullable=True)
    verification_expires_at = Column(String(40), nullable=True)
    verification_sent_at = Column(String(40), nullable=True)
    verification_attempts = Column(Integer, nullable=False, default=0)
    tier = Column(String(20), nullable=False, default="free")
    handoffs_used = Column(Integer, nullable=False, default=0)
    period_month = Column(String(7), nullable=False, default="")
    cycle_start = Column(String(10), nullable=True)
    cycle_end = Column(String(10), nullable=True)
    cycle_tier = Column(String(20), nullable=False, default="free")
    access_expires_at = Column(String(40), nullable=True)
    created_at = Column(String(40), nullable=False)


class AgentModel(Base):
    __tablename__ = "agents"

    agent_id = Column(String(40), primary_key=True, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    name = Column(String(150), nullable=False)
    description = Column(Text, nullable=True)
    capabilities_json = Column(Text, nullable=False, default="[]")
    endpoint_url = Column(Text, nullable=True)
    public_key_b64 = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, default="ACTIVE")
    card_signature_b64 = Column(Text, nullable=False, default="")
    is_overage = Column(Boolean, nullable=False, default=False)
    created_at = Column(String(40), nullable=False)


class HandoffModel(Base):
    __tablename__ = "handoffs"

    handoff_id = Column(String(40), primary_key=True, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    from_agent_id = Column(String(40), nullable=False, index=True)
    to_agent_id = Column(String(40), nullable=False, index=True)
    parent_handoff_id = Column(String(40), nullable=True, index=True)
    task_hash = Column(String(64), nullable=False)
    scope_json = Column(Text, nullable=False)
    signature_b64 = Column(Text, nullable=False)
    signer_public_key_b64 = Column(Text, nullable=False)
    created_at = Column(String(40), nullable=False)


class AuditEventModel(Base):
    __tablename__ = "audit_events"

    event_id = Column(String(36), primary_key=True)
    client_id = Column(String(100), nullable=True, index=True)
    action = Column(String(80), nullable=False)
    target_type = Column(String(32), nullable=False)
    target_id = Column(String(100), nullable=False)
    metadata_json = Column(Text, nullable=False, default="{}")
    created_at = Column(String(40), nullable=False)


class BillingHistoryModel(Base):
    __tablename__ = "billing_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    client_id = Column(String(100), nullable=False, index=True)
    action = Column(String(60), nullable=False)
    cashfree_order_id = Column(String(128), unique=True, nullable=False, index=True)
    cashfree_payment_id = Column(String(128), nullable=True)
    tier = Column(String(20), nullable=False)
    details = Column(Text, nullable=False)
    created_at = Column(String(40), nullable=False)


class OverageLedgerModel(Base):
    __tablename__ = "overage_ledger"

    id = Column(Integer, primary_key=True, autoincrement=True)
    client_id = Column(String(100), nullable=False, index=True)
    cycle_start = Column(String(10), nullable=False, index=True)
    cycle_end = Column(String(10), nullable=False)
    usage_type = Column(String(20), nullable=False)
    units = Column(Integer, nullable=False, default=1)
    unit_price_microdollars = Column(Integer, nullable=False)
    tier = Column(String(20), nullable=False)
    reference_id = Column(String(40), nullable=True)
    created_at = Column(String(40), nullable=False)


class BillingStatementModel(Base):
    __tablename__ = "billing_statements"

    id = Column(Integer, primary_key=True, autoincrement=True)
    client_id = Column(String(100), nullable=False, index=True)
    cycle_start = Column(String(10), nullable=False, index=True)
    cycle_end = Column(String(10), nullable=False)
    tier = Column(String(20), nullable=False)
    amount_microdollars = Column(Integer, nullable=False)
    payment_status = Column(String(20), nullable=False, default="unpaid")
    cashfree_order_id = Column(String(128), nullable=True, unique=True)
    cashfree_payment_id = Column(String(128), nullable=True)
    paid_at = Column(String(40), nullable=True)
    created_at = Column(String(40), nullable=False)


class RateLimitCounterModel(Base):
    __tablename__ = "rate_limit_counters"

    bucket_key = Column(String(64), primary_key=True)
    window_start = Column(Integer, nullable=False)
    request_count = Column(Integer, nullable=False, default=0)


IMMUTABLE_TABLES = (
    "agents",
    "handoffs",
    "audit_events",
    "billing_history",
    "overage_ledger",
)

_SHARED_RATE_LIMIT_SQL = text(
    """
    INSERT INTO rate_limit_counters (bucket_key, window_start, request_count)
    VALUES (:bucket_key, :window_start, 1)
    ON CONFLICT (bucket_key) DO UPDATE
    SET window_start = EXCLUDED.window_start,
        request_count = CASE
            WHEN rate_limit_counters.window_start = EXCLUDED.window_start
            THEN rate_limit_counters.request_count + 1
            ELSE 1
        END
    RETURNING request_count
    """
)


def _consume_local_rate_limit(bucket_key: str) -> bool:
    now = time.monotonic()
    bucket = _rate_bucket.setdefault(bucket_key, [])
    bucket[:] = [stamp for stamp in bucket if stamp > now - 60.0]
    if len(bucket) >= RATE_LIMIT_PER_MIN:
        return False
    bucket.append(now)
    return True


async def _consume_shared_rate_limit(bucket_key: str) -> bool:
    """Atomically consume one request from a shared fixed 60-second window."""
    window_start = int(time.time()) // 60
    try:
        async with SessionLocal() as session:
            result = await session.execute(
                _SHARED_RATE_LIMIT_SQL,
                {"bucket_key": bucket_key, "window_start": window_start},
            )
            request_count = int(result.scalar_one())
            await session.commit()
        return request_count <= RATE_LIMIT_PER_MIN
    except SQLAlchemyError:
        logger.exception("Shared rate limit check failed; failing closed")
        return False


async def _consume_rate_limit(bucket_key: str) -> bool:
    if DATABASE_URL.startswith("postgresql"):
        return await _consume_shared_rate_limit(bucket_key)
    return _consume_local_rate_limit(bucket_key)


async def _ensure_schema() -> None:
    """Create tables, backfill signatures, then install immutability guards."""
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        dialect = engine.dialect.name

        async def column_names(table_name: str) -> set[str]:
            if dialect == "sqlite":
                result = await connection.execute(text(f"PRAGMA table_info({table_name})"))
                return {row[1] for row in result.fetchall()}
            result = await connection.execute(
                text("SELECT column_name FROM information_schema.columns WHERE table_name = :table_name"),
                {"table_name": table_name},
            )
            return {row[0] for row in result.fetchall()}

        agent_columns = await column_names("agents")
        if "card_signature_b64" not in agent_columns:
            await connection.execute(
                text("ALTER TABLE agents ADD COLUMN card_signature_b64 TEXT NOT NULL DEFAULT ''")
            )
        if "is_overage" not in agent_columns:
            await connection.execute(
                text("ALTER TABLE agents ADD COLUMN is_overage BOOLEAN NOT NULL DEFAULT 0")
            )

        client_columns = await column_names("clients")
        if "email" not in client_columns:
            await connection.execute(text("ALTER TABLE clients ADD COLUMN email VARCHAR(320)"))
            client_columns.add("email")
        if "email" in client_columns:
            await connection.execute(
                text("CREATE INDEX IF NOT EXISTS ix_clients_email ON clients (email)")
            )
        if "cycle_start" not in client_columns:
            await connection.execute(text("ALTER TABLE clients ADD COLUMN cycle_start TEXT"))
        if "cycle_end" not in client_columns:
            await connection.execute(text("ALTER TABLE clients ADD COLUMN cycle_end TEXT"))
        if "cycle_tier" not in client_columns:
            await connection.execute(
                text("ALTER TABLE clients ADD COLUMN cycle_tier TEXT NOT NULL DEFAULT 'free'")
            )

        legacy_clients = await connection.execute(
            text(
                "SELECT client_id, created_at, tier FROM clients "
                "WHERE cycle_start IS NULL OR cycle_start = ''"
            )
        )
        for row in legacy_clients.fetchall():
            item = dict(row._mapping)
            start = _parse_date(str(item["created_at"])[:10]) or datetime.now(timezone.utc).date()
            await connection.execute(
                text(
                    "UPDATE clients SET cycle_start = :start, cycle_end = :end, "
                    "cycle_tier = :tier WHERE client_id = :client_id"
                ),
                {
                    "start": start.isoformat(),
                    "end": _next_cycle_date(start).isoformat(),
                    "tier": item["tier"],
                    "client_id": item["client_id"],
                },
            )

        rows = await connection.execute(
            text(
                "SELECT agent_id, name, description, capabilities_json, endpoint_url, "
                "public_key_b64, status, created_at FROM agents "
                "WHERE card_signature_b64 IS NULL OR card_signature_b64 = ''"
            )
        )
        for row in rows.fetchall():
            item = dict(row._mapping)
            payload = {
                "v": 1,
                "agent_id": item["agent_id"],
                "name": item["name"],
                "description": item["description"] or "",
                "capabilities": json.loads(item["capabilities_json"]),
                "endpoint": item["endpoint_url"] or "",
                "public_key": item["public_key_b64"],
                "status": item["status"],
                "issued_at": item["created_at"],
            }
            await connection.execute(
                text("UPDATE agents SET card_signature_b64 = :sig WHERE agent_id = :agent_id"),
                {"sig": sign_platform(payload), "agent_id": item["agent_id"]},
            )

        if dialect == "sqlite":
            for table in IMMUTABLE_TABLES:
                await connection.execute(
                    text(
                        f"CREATE TRIGGER IF NOT EXISTS ag_{table}_no_update BEFORE UPDATE ON {table} "
                        "BEGIN SELECT RAISE(ABORT, 'immutable record'); END;"
                    )
                )
                await connection.execute(
                    text(
                        f"CREATE TRIGGER IF NOT EXISTS ag_{table}_no_delete BEFORE DELETE ON {table} "
                        "BEGIN SELECT RAISE(ABORT, 'immutable record'); END;"
                    )
                )
        else:
            await connection.execute(
                text(
                    "CREATE OR REPLACE FUNCTION agentgrid_immutable_guard() RETURNS trigger AS $$ "
                    "BEGIN RAISE EXCEPTION 'immutable record'; END; $$ LANGUAGE plpgsql;"
                )
            )
            for table in IMMUTABLE_TABLES:
                await connection.execute(
                    text(f"DROP TRIGGER IF EXISTS ag_{table}_immutable ON {table};")
                )
                await connection.execute(
                    text(
                        f"CREATE TRIGGER ag_{table}_immutable BEFORE UPDATE OR DELETE ON {table} "
                        "FOR EACH ROW EXECUTE FUNCTION agentgrid_immutable_guard();"
                    )
                )


@asynccontextmanager
async def lifespan(app: FastAPI):
    if SKIP_SCHEMA_ON_STARTUP:
        logger.info(
            "Startup migrations are disabled; run `python migrate.py` before serving traffic."
        )
    else:
        await _ensure_schema()
    yield


app = FastAPI(
    title="AgentGrid",
    version="0.1.0",
    description=(
        "Signed identity, discovery and handoff receipts for AI agents.\n\n"
        "## Three steps to your first handoff\n\n"
        "```bash\n"
        "pip install theoc-agentgrid-protocol\n"
        "agrid register --email you@example.com\n"
        "agrid verify <6-digit-code-from-your-inbox>  # first handoff runs automatically\n"
        "agrid card <agent_id>\n"
        "agrid receipts <agent_id>\n"
        "```\n\n"
        "A real email is required. The API key is created only after you confirm "
        "the emailed code, so unverified signups cannot use the service. "
        "`agrid verify` immediately runs a real signed handoff; use "
        "`agrid quickstart` any time for another demo and `--no-quickstart` to "
        "skip it. Accounts created before email verification can run "
        "`agrid update --email you@example.com` and then `agrid verify <code>`; "
        "the old key is replaced at that point. Copy-paste recipes (offline verify, "
        "scoped handoff, receipt read), a LangGraph/CrewAI/OpenAI Agents drop-in, "
        "and the FAQ live in the [developer guide](/guide). Registration is open "
        "self-service; payments happen outside AgentGrid."
    ),
    lifespan=lifespan,
)
origins = [o.strip() for o in os.environ.get("AGENTGRID_CORS_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-AgentGrid-API-Key", "X-AgentGrid-Admin-Key", "X-AgentGrid-Admin-MFA"],
)


def _with_security_headers(response, path: str = ""):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if path == "/ops-lite" or path.startswith("/ops-lite/"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'; "
            f"connect-src 'self'; form-action 'self'; "
            f"frame-ancestors {OPS_LITE_FRAME_ANCESTORS}; base-uri 'none'"
        )
        if OPS_LITE_FRAME_ANCESTORS.strip() == "'self'":
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
        else:
            response.headers.pop("X-Frame-Options", None)
    else:
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
    return response


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    path = request.url.path
    exempt = (
        path.startswith("/health")
        or path in {"/", "/docs", "/openapi.json", "/redoc", "/robots.txt", "/sitemap.xml"}
        or (path.startswith("/google") and path.endswith(".html"))
    )

    if not exempt:
        length_header = request.headers.get("content-length")
        if length_header:
            try:
                if int(length_header) > MAX_BODY_BYTES:
                    return _with_security_headers(
                        JSONResponse(status_code=413, content={"detail": "Request body too large."}),
                        path,
                    )
            except ValueError:
                pass

        if RATE_LIMIT_PER_MIN > 0:
            identity = request.headers.get("x-agentgrid-api-key") or (
                request.client.host if request.client else "unknown"
            )
            bucket_key = hashlib.sha256(identity.encode("utf-8")).hexdigest()
            if not await _consume_rate_limit(bucket_key):
                return _with_security_headers(
                    JSONResponse(status_code=429, content={"detail": "Too many requests."}),
                    path,
                )

    response = await call_next(request)
    return _with_security_headers(response, path)


class BodyLimitMiddleware:
    """Reject oversized bodies even when Content-Length is missing or chunked."""

    def __init__(self, app):
        self.app = app

    @staticmethod
    async def _too_large(scope, receive, send) -> None:
        response = JSONResponse(status_code=413, content={"detail": "Request body too large."})
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        await response(scope, receive, send)

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path.startswith("/health") or path in {"/", "/docs", "/openapi.json", "/redoc"}:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        declared = headers.get(b"content-length")
        if declared:
            try:
                if int(declared) > MAX_BODY_BYTES:
                    await self._too_large(scope, receive, send)
                    return
            except ValueError:
                pass

        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > MAX_BODY_BYTES:
                await self._too_large(scope, receive, send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(chunks)

        async def replay_receive():
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay_receive, send)


app.add_middleware(BodyLimitMiddleware)


async def get_db() -> AsyncSession:
    async with SessionLocal() as session:
        yield session


async def verify_api_key(
    x_agentgrid_api_key: Optional[str] = Header(None, alias="X-AgentGrid-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> str:
    if not x_agentgrid_api_key or not API_KEY_PATTERN.fullmatch(x_agentgrid_api_key):
        raise HTTPException(status_code=401, detail="Valid X-AgentGrid-API-Key header required.")
    result = await db.execute(
        select(ClientModel).where(ClientModel.api_key_hash == hash_api_key(x_agentgrid_api_key))
    )
    client = result.scalar_one_or_none()
    if not client or not client.email_verified:
        raise HTTPException(status_code=401, detail="Access Denied: invalid API key.")
    return client.client_id


def _check_admin_credentials(admin_key: Optional[str], mfa: Optional[str]) -> None:
    if not ADMIN_KEY or not admin_key or not hmac.compare_digest(admin_key, ADMIN_KEY):
        raise HTTPException(status_code=401, detail="Valid X-AgentGrid-Admin-Key header required.")
    if ADMIN_MFA_SECRET:
        if not mfa or not _verify_totp(ADMIN_MFA_SECRET, mfa):
            raise HTTPException(status_code=401, detail="Valid X-AgentGrid-Admin-MFA TOTP code required.")
    elif APP_ENV == "production":
        raise HTTPException(status_code=503, detail="Admin MFA is not configured; set AGENTGRID_ADMIN_MFA_SECRET.")


async def verify_admin(
    x_agentgrid_admin_key: Optional[str] = Header(None, alias="X-AgentGrid-Admin-Key"),
    x_agentgrid_admin_mfa: Optional[str] = Header(None, alias="X-AgentGrid-Admin-MFA"),
) -> bool:
    _check_admin_credentials(x_agentgrid_admin_key, x_agentgrid_admin_mfa)
    return True


OPS_SESSION_COOKIE = "ag_ops"
OPS_SESSION_TTL_SECONDS = 12 * 60 * 60
OPS_LITE_COOKIE = "ag_lite"
OPS_LITE_TTL_SECONDS = 30 * 24 * 60 * 60


def _ops_secret() -> bytes:
    return (
        os.environ.get("AGENTGRID_SIGNING_KEY_B64")
        or ADMIN_KEY
        or "agentgrid-development"
    ).encode("utf-8")


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _make_signed_scope_token(scope: str, ttl_seconds: int) -> str:
    payload = {"scope": scope, "exp": int(time.time()) + ttl_seconds}
    body = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = _b64url_encode(
        hmac.new(_ops_secret(), body.encode("utf-8"), hashlib.sha256).digest()
    )
    return f"{body}.{signature}"


def _signed_scope_token_valid(token: Optional[str], scope: str) -> bool:
    if not token or "." not in token:
        return False
    body, supplied = token.split(".", 1)
    expected = _b64url_encode(
        hmac.new(_ops_secret(), body.encode("utf-8"), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(supplied, expected):
        return False
    try:
        payload = json.loads(_b64url_decode(body))
        return payload.get("scope") == scope and int(payload.get("exp", 0)) > int(time.time())
    except (ValueError, TypeError, binascii.Error):
        return False


def _make_ops_session_token() -> str:
    return _make_signed_scope_token("ops:read", OPS_SESSION_TTL_SECONDS)


def _ops_session_valid(token: Optional[str]) -> bool:
    return _signed_scope_token_valid(token, "ops:read")


def _make_ops_lite_token() -> str:
    return _make_signed_scope_token("ops:lite:read", OPS_LITE_TTL_SECONDS)


def _ops_lite_session_valid(token: Optional[str]) -> bool:
    return _signed_scope_token_valid(token, "ops:lite:read")


def _check_ops_lite_credentials(key: str, catch_phrase: str) -> None:
    if not OPS_LITE_KEY or not OPS_LITE_CATCH:
        raise HTTPException(status_code=503, detail="Read-only operator view is not configured.")
    if (
        not key
        or not catch_phrase
        or not hmac.compare_digest(key, OPS_LITE_KEY)
        or not hmac.compare_digest(catch_phrase, OPS_LITE_CATCH)
    ):
        raise HTTPException(status_code=401, detail="Invalid read key or catch phrase.")


async def verify_ops_or_admin(
    request: Request,
    x_agentgrid_admin_key: Optional[str] = Header(None, alias="X-AgentGrid-Admin-Key"),
    x_agentgrid_admin_mfa: Optional[str] = Header(None, alias="X-AgentGrid-Admin-MFA"),
) -> bool:
    """Allow a read-only session cookie or the existing admin key + TOTP headers."""
    if _ops_session_valid(request.cookies.get(OPS_SESSION_COOKIE)):
        return True
    if _ops_lite_session_valid(request.cookies.get(OPS_LITE_COOKIE)):
        return True
    _check_admin_credentials(x_agentgrid_admin_key, x_agentgrid_admin_mfa)
    return True


def record_audit(
    db: AsyncSession,
    *,
    client_id: Optional[str],
    action: str,
    target_type: str,
    target_id: str,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    db.add(
        AuditEventModel(
            event_id=str(uuid.uuid4()),
            client_id=client_id,
            action=action[:80],
            target_type=target_type[:32],
            target_id=target_id[:100],
            metadata_json=json.dumps(_safe_audit_metadata(metadata), sort_keys=True, separators=(",", ":"), allow_nan=False),
            created_at=_now_iso(),
        )
    )


def _client_stmt(client_id: str):
    stmt = select(ClientModel).where(ClientModel.client_id == client_id)
    if engine.dialect.name == "postgresql":
        stmt = stmt.with_for_update()
    return stmt


def active_tier(client: ClientModel) -> str:
    expiry = _parse_iso(client.access_expires_at)
    if expiry and expiry < datetime.now(timezone.utc):
        return "free"
    return client.tier if client.tier in TIER_LIMITS else "free"


def cycle_bounds(client: ClientModel) -> tuple[date, date]:
    today = datetime.now(timezone.utc).date()
    start = _parse_date(client.cycle_start) or _parse_date(str(client.created_at)[:10]) or today
    end = _parse_date(client.cycle_end) or _next_cycle_date(start)
    return start, end


async def ensure_current_period(client: ClientModel, db: AsyncSession) -> None:
    """Roll one or more closed cycles forward, snapshotting each closed statement."""
    start, end = cycle_bounds(client)
    today = datetime.now(timezone.utc).date()
    while today >= end:
        closed_tier = client.cycle_tier or active_tier(client)
        await _get_or_create_statement(
            db,
            client_id=client.client_id,
            cycle_start=start.isoformat(),
            cycle_end=end.isoformat(),
            tier=closed_tier,
        )
        next_end = _next_cycle_date(end)
        if next_end <= end:
            break
        start = end
        end = next_end
    if client.cycle_start != start.isoformat():
        client.cycle_start = start.isoformat()
        client.cycle_end = end.isoformat()
        client.period_month = start.strftime("%Y-%m")
        client.handoffs_used = 0
        client.cycle_tier = active_tier(client)


def agent_card(agent: AgentModel) -> dict[str, Any]:
    return {
        "v": 1,
        "agent_id": agent.agent_id,
        "name": agent.name,
        "description": agent.description or "",
        "capabilities": json.loads(agent.capabilities_json),
        "endpoint": agent.endpoint_url or "",
        "public_key": agent.public_key_b64,
        "status": agent.status,
        "issued_at": agent.created_at,
    }


def signed_card(agent: AgentModel) -> dict[str, Any]:
    card = agent_card(agent)
    signature = agent.card_signature_b64 or sign_platform(card)
    return {**card, "signature": signature, "verify_url": f"/v1/agents/{agent.agent_id}/verify"}


def scope_is_subset(child: dict[str, Any], parent: dict[str, Any]) -> bool:
    if not isinstance(child, dict) or not isinstance(parent, dict):
        return False
    if "allowed" in child:
        if "allowed" not in parent:
            return False
        if not isinstance(child["allowed"], list) or not isinstance(parent["allowed"], list):
            return False
        if not set(child["allowed"]).issubset(set(parent["allowed"])):
            return False
    if "max_actions" in child:
        if "max_actions" not in parent:
            return False
        try:
            if int(child["max_actions"]) > int(parent["max_actions"]):
                return False
        except (TypeError, ValueError):
            return False
    return True


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------
class RegisterClientRequest(BaseModel):
    client_id: Optional[str] = Field(None, min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")
    email: str = Field(
        ...,
        max_length=320,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        description="Required. A code is sent here to confirm a real human before a key is issued.",
    )


class VerifyEmailRequest(BaseModel):
    client_id: str = Field(..., min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")
    code: str = Field(..., min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


class ResendVerificationRequest(BaseModel):
    client_id: str = Field(..., min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")


class UpdateEmailRequest(BaseModel):
    email: str = Field(..., max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class CreateAgentRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=150)
    description: Optional[str] = Field(None, max_length=1000)
    capabilities: list[str] = Field(default_factory=list, max_length=50)
    endpoint_url: Optional[str] = Field(None, max_length=500)
    public_key: str = Field(..., min_length=20, max_length=100)


class CreateHandoffRequest(BaseModel):
    handoff_id: str = Field(..., min_length=34, max_length=34)
    to_agent_id: str = Field(..., min_length=1, max_length=40)
    task_hash: str = Field(..., min_length=64, max_length=64)
    scope: dict[str, Any]
    created_at: str = Field(..., min_length=10, max_length=40)
    signature: str = Field(..., min_length=20, max_length=200)
    parent_handoff_id: Optional[str] = Field(None, max_length=40)


class GrantAccessRequest(BaseModel):
    tier: str = Field(..., pattern=r"^(plus|pro|enterprise)$")
    cashfree_order_id: str = Field(..., min_length=3, max_length=128)
    cashfree_payment_id: Optional[str] = Field(None, max_length=128)
    grant_reason: str = Field(
        "external_payment",
        pattern=r"^(external_payment|operator_comp|operator_test|operator_support)$",
    )
    reason_note: Optional[str] = Field(None, max_length=200)


class RecordStatementPaymentRequest(BaseModel):
    cashfree_order_id: str = Field(..., min_length=3, max_length=128)
    cashfree_payment_id: Optional[str] = Field(None, max_length=128)


class AdminSessionRequest(BaseModel):
    admin_key: str = Field(..., min_length=1)
    mfa: str = Field(..., min_length=1, max_length=6)




# ---------------------------------------------------------------------------
# Health + root
# ---------------------------------------------------------------------------
@app.get("/health/live")
async def health_live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
async def health_ready(db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    try:
        await db.execute(select(ClientModel).limit(1))
        return {"status": "ready", "database": "connected", "api_version": "0.1.0"}
    except Exception as exc:
        logger.error("Readiness check failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


PUBLIC_STYLE = """
<style>
:root{color-scheme:dark}
body{font:16px/1.65 system-ui;max-width:920px;margin:6vh auto;padding:0 22px;background:#0b1020;color:#eaf0ff}
h1{font-size:2.5rem;margin-bottom:.2rem}h2{margin-top:2.4rem;border-bottom:1px solid #233056;padding-bottom:.35rem}
h3{margin-bottom:.3rem}code,pre{background:#151d36;border-radius:6px}code{padding:2px 6px}
pre{padding:14px;overflow:auto}a{color:#7ee7c7}table{width:100%;border-collapse:collapse}
td,th{padding:9px 8px;border-bottom:1px solid #233056;text-align:left;vertical-align:top}
.note{background:#12233a;border-radius:8px;padding:12px 16px}.muted{color:#9db0d0}
.tag{display:inline-block;background:#15392f;color:#7ee7c7;border-radius:99px;padding:2px 10px;font-size:.85rem}
</style>
"""


def _json_ld(payload: dict[str, Any]) -> str:
    """Serialize structured data safely inside an HTML script tag."""
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).replace("<", "\\u003c")
    return '<script type="application/ld+json">' + body + "</script>"


def _seo_meta(
    title: str,
    description: str,
    path: str,
    *,
    structured_data: Optional[dict[str, Any]] = None,
    robots: str = "index, follow",
) -> str:
    """Shared canonical, social, and crawler metadata for public HTML pages."""
    canonical = PUBLIC_BASE_URL + path
    parts = [
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>{html.escape(title)}</title>",
        f'<meta name="description" content="{html.escape(description, quote=True)}">',
        f'<meta name="robots" content="{html.escape(robots, quote=True)}">',
        f'<link rel="canonical" href="{html.escape(canonical, quote=True)}">',
        '<meta property="og:type" content="website">',
        '<meta property="og:site_name" content="AgentGrid">',
        f'<meta property="og:title" content="{html.escape(title, quote=True)}">',
        f'<meta property="og:description" content="{html.escape(description, quote=True)}">',
        f'<meta property="og:url" content="{html.escape(canonical, quote=True)}">',
        '<meta name="twitter:card" content="summary">',
        f'<meta name="twitter:title" content="{html.escape(title, quote=True)}">',
        f'<meta name="twitter:description" content="{html.escape(description, quote=True)}">',
    ]
    if structured_data:
        parts.append(_json_ld(structured_data))
    return "\n".join(parts)


LANDING_STRUCTURED_DATA: dict[str, Any] = {
    "@context": "https://schema.org",
    "@graph": [
        {
            "@type": "Organization",
            "@id": PUBLIC_BASE_URL + "/#organization",
            "name": "TheoC Computations",
            "url": "https://github.com/TheoCComputationsmain",
        },
        {
            "@type": "WebSite",
            "@id": PUBLIC_BASE_URL + "/#website",
            "url": PUBLIC_BASE_URL + "/",
            "name": "AgentGrid",
            "description": "Signed identity, discovery, and handoff receipts for AI agents.",
            "inLanguage": "en",
            "publisher": {"@id": PUBLIC_BASE_URL + "/#organization"},
        },
        {
            "@type": "SoftwareApplication",
            "@id": PUBLIC_BASE_URL + "/#software",
            "name": "AgentGrid",
            "applicationCategory": "DeveloperApplication",
            "operatingSystem": "Web",
            "url": PUBLIC_BASE_URL + "/",
            "description": (
                "Publish signed agent cards, verify them offline, and record scoped "
                "handoffs with immutable receipts. Payments happen externally."
            ),
            "offers": {
                "@type": "Offer",
                "price": "0",
                "priceCurrency": "USD",
                "description": "Free tier. Paid tiers are collected outside AgentGrid.",
            },
        },
    ],
}

LANDING_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
""" + _seo_meta(
    "AgentGrid — signed identity and handoff receipts for AI agents",
    "AgentGrid publishes signed agent cards, offline verification, scoped handoffs, and immutable receipts. Open self-service registration; no money inside the platform.",
    "/",
    structured_data=LANDING_STRUCTURED_DATA,
) + PUBLIC_STYLE + """</head><body>
<h1>AgentGrid</h1>
<p class="muted">Signed identity, discovery and handoff receipts for AI agents.</p>
<p><span class="tag">Portable signed cards</span> <span class="tag">Verified handoffs</span>
<span class="tag">Immutable receipts</span> <span class="tag">External payments only</span></p>

<p>AgentGrid is infrastructure for agents, not another chatbot. Register an agent,
publish a signed capability card anyone can verify offline, and record signed
handoffs between agents with scoped, immutable receipts. Usage is metered in a
ledger; money never enters the platform.</p>

<h2>Get a signed handoff without writing code</h2>
<p><strong>No-code option:</strong> <a href="/quickstart">open the browser quickstart</a>. Enter your
email, confirm the 6-digit code, and we show your two agents, signed handoff, and immutable receipt.
No wallet, card, or CLI needed.</p>
<p class="muted">Prefer the CLI? It is still three commands:</p>
<pre>pip install theoc-agentgrid-protocol
agrid register --email you@example.com
agrid verify 123456       # code from inbox; first handoff runs automatically</pre>
<p><code>agrid register</code> is open self-service — no invite token — but a real email is
required. We send a 6-digit code; your <code>agk_...</code> key is created only after
<code>agrid verify</code>, then stored locally without printing it. Unverified signups have no
usable key. Verification immediately registers two agents, verifies a card online and
offline, signs a handoff, and prints the receipt — no fourth command. Use
<code>agrid quickstart</code> any time for another demo, or
<code>agrid verify &lt;code&gt; --no-quickstart</code> to skip it. See the
<a href="/guide">developer guide</a> for Python usage, framework drop-ins, and API details.</p>

<div class="note"><strong>Already using AgentGrid from before email verification?</strong>
Run <code>agrid doctor</code> with your existing key. Legacy accounts automatically show a
self-service update command; no one needs to contact you. You can also go straight to
<code>agrid update --email you@example.com</code> and then <code>agrid verify &lt;code&gt;</code>.</div>

<h2>Pricing</h2>
<table><thead><tr><th>Tier</th><th>Base</th><th>Agents</th><th>Handoffs / cycle</th><th>Pay</th></tr></thead>
<tbody>
<tr><td>Free</td><td>$0</td><td>5</td><td>100</td><td>No payment needed</td></tr>
<tr><td>Plus</td><td>$20</td><td>100</td><td>10,000</td><td><a href="https://payments.cashfree.com/forms/agentgrid-plus" target="_blank" rel="noopener">₹1,700</a></td></tr>
<tr><td>Pro</td><td>$150</td><td>1,000</td><td>100,000</td><td><a href="https://payments.cashfree.com/forms/agentgrid-pro" target="_blank" rel="noopener">₹12,750</a></td></tr>
<tr><td>Enterprise</td><td>Custom $2,500–$5,000</td><td>10,000</td><td>1,000,000</td><td><a href="https://payments.cashfree.com/forms/agentgrid-enterprise" target="_blank" rel="noopener">Self-service</a> (₹212,500–₹425,000)</td></tr>
</tbody></table>
<p class="muted">A cycle is one rolling month anchored to signup day. All tiers, including Free,
allow overage at $1 per 1,000 extra handoffs and $0.10 per extra agent per day, up to a
3× hard cap. External collection uses a fixed ₹85 = $1 conversion; all internal
statements remain in USD.</p>

<div class="note"><strong>No money inside AgentGrid.</strong> No wallet, escrow, auto top-up,
in-app checkout, or automatic deduction. Register first with the email you will use to pay,
get your Client ID, then open the payment link for your tier and enter that exact
<strong>AgentGrid Client ID</strong> in the form's required field. Use the same email on
the payment form so we can fix a mistyped Client ID automatically. Your tier upgrades
automatically once payment is confirmed. The invoice ID on
your statement is only for operator reconciliation.</div>

<h2>Explore</h2>
<p><a href="/guide">Developer guide</a> &middot; <a href="/docs">API reference</a> &middot;
<a href="/openapi.json">OpenAPI</a> &middot; <a href="/v1/agents/public-key">Platform public key</a> &middot;
<a href="/health/ready">Health</a></p>
<p><strong>Write-up:</strong> <a href="https://dev.to/theoc_computations_21b3c7/i-built-a-signed-handoff-layer-for-ai-agents-and-you-can-verify-it-offline-5alh">I built a signed handoff layer for AI agents (and you can verify it offline)</a></p>
</body></html>"""

GUIDE_STRUCTURED_DATA: dict[str, Any] = {
    "@context": "https://schema.org",
    "@graph": [
        {
            "@type": "BreadcrumbList",
            "@id": PUBLIC_BASE_URL + "/guide#breadcrumb",
            "itemListElement": [
                {
                    "@type": "ListItem",
                    "position": 1,
                    "name": "AgentGrid",
                    "item": PUBLIC_BASE_URL + "/",
                },
                {
                    "@type": "ListItem",
                    "position": 2,
                    "name": "Developer guide",
                    "item": PUBLIC_BASE_URL + "/guide",
                },
            ],
        },
        {
            "@type": "TechArticle",
            "@id": PUBLIC_BASE_URL + "/guide#article",
            "headline": "AgentGrid developer guide: signed cards, scoped handoffs, and receipts",
            "description": (
                "Copy-paste recipes for registering a client, verifying signed agent "
                "cards offline, recording scoped handoffs, and reading immutable receipts."
            ),
            "inLanguage": "en",
            "dateModified": date.today().isoformat(),
            "author": {"@id": PUBLIC_BASE_URL + "/#organization"},
            "publisher": {"@id": PUBLIC_BASE_URL + "/#organization"},
            "mainEntityOfPage": {"@type": "WebPage", "@id": PUBLIC_BASE_URL + "/guide"},
            "breadcrumb": {"@id": PUBLIC_BASE_URL + "/guide#breadcrumb"},
        },
        {
            "@type": "FAQPage",
            "@id": PUBLIC_BASE_URL + "/guide#faq",
            "mainEntity": [
                {
                    "@type": "Question",
                    "name": "Do I need an invite token or approval?",
                    "acceptedAnswer": {
                        "@type": "Answer",
                        "text": (
                            "No. agrid register is open self-service. You do need a real "
                            "email: a 6-digit code is sent there and the API key is created "
                            "only after you confirm it."
                        ),
                    },
                },
                {
                    "@type": "Question",
                    "name": "I signed up before email verification. How do I update?",
                    "acceptedAnswer": {
                        "@type": "Answer",
                        "text": (
                            "Run agrid update --email you@example.com with your existing "
                            "local key, then agrid verify <code> with the emailed code. "
                            "Your key is replaced at verification."
                        ),
                    },
                },
                {
                    "@type": "Question",
                    "name": "Does email verification prove I am human?",
                    "acceptedAnswer": {
                        "@type": "Answer",
                        "text": (
                            "It proves you control the inbox at signup, which blocks random "
                            "bot signups and makes every account reachable. It is not a "
                            "biometric or CAPTCHA-style proof."
                        ),
                    },
                },
                {
                    "@type": "Question",
                    "name": "Where is my API key? The CLI did not print it.",
                    "acceptedAnswer": {
                        "@type": "Answer",
                        "text": (
                            "The service shows the key once and the CLI writes it to "
                            "~/.agentgrid/credentials.json without printing it. Back up "
                            "that file; there is no secret recovery endpoint."
                        ),
                    },
                },
                {
                    "@type": "Question",
                    "name": "Do I need a payment method to start?",
                    "acceptedAnswer": {
                        "@type": "Answer",
                        "text": (
                            "No. The free tier needs no card. Payments are entirely "
                            "external; AgentGrid has no wallet, escrow, checkout, or "
                            "automatic deduction."
                        ),
                    },
                },
            ],
        },
    ],
}

GUIDE_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
""" + _seo_meta(
    "AgentGrid developer guide — signed cards, scoped handoffs, receipts",
    "Install AgentGrid, verify signed agent cards offline, record scoped handoffs, read immutable receipts, and upgrade pre-email accounts.",
    "/guide",
    structured_data=GUIDE_STRUCTURED_DATA,
) + PUBLIC_STYLE + """</head><body>
<h1>Developer guide</h1>
<p><a href="/">&larr; Home</a></p>
<p><strong>Write-up:</strong> <a href="https://dev.to/theoc_computations_21b3c7/i-built-a-signed-handoff-layer-for-ai-agents-and-you-can-verify-it-offline-5alh">I built a signed handoff layer for AI agents (and you can verify it offline)</a> — design notes and the full walkthrough.</p>

<h2 id="quickstart">Start here: 3 steps (~1 minute), or no code</h2>
<p><strong>No code:</strong> use the <a href="/quickstart">browser quickstart</a>. It verifies your
email, creates two demo agents, signs a scoped handoff, and shows the receipt. Demo keys are
generated on the server and discarded; use the CLI/SDK when private keys must stay on your machine.</p>
<p class="muted">The command path below does the same thing locally with your own keys:</p>
<ol>
<li><strong>Install and register.</strong> Run <code>pip install theoc-agentgrid-protocol</code>,
then <code>agrid register --email you@example.com</code>. It is free and open — no invite token
or card — but a real email is required. Check your inbox for a 6-digit code.</li>
<li><strong>Verify and see a receipt.</strong> <code>agrid verify 123456</code> creates your
<code>agk_...</code> key, stores it locally without printing it, and immediately runs a real
handoff: two agents, an online and offline card check, a signed delegation, and its immutable
receipt. Back up the key. Pass <code>--no-quickstart</code> to skip the demo.</li>
<li><strong>Check the work.</strong> <code>agrid card &lt;agent_id&gt;</code> verifies a public
card offline; <code>agrid receipts &lt;agent_id&gt;</code> reads the immutable receipts. Use
<code>agrid quickstart</code> any time for another demo.</li>
</ol>
<pre>pip install theoc-agentgrid-protocol
agrid register --email you@example.com
agrid verify 123456          # code emailed to you; first handoff runs automatically
agrid card &lt;agent_id&gt;      # an ag_... ID from step 2
agrid receipts &lt;agent_id&gt;  # the worker ID from step 2</pre>
<p class="muted">Already have a key? Use <code>agrid login</code> or set <code>AGENTGRID_API_KEY</code>.
Need a framework drop-in? Copy <code>examples/langgraph_handoff.py</code> from the repository
into your LangGraph, CrewAI, or OpenAI Agents SDK project. Stuck? Jump to the <a href="#faq">FAQ</a>.</p>

<p><strong>Pre-email legacy account?</strong> Your own CLI will surface the update command when you
run <code>agrid doctor</code>, <code>agrid quickstart</code>, <code>agrid statement</code>,
<code>agrid receipts</code>, or <code>agrid login</code>. The API also returns
<code>legacy_upgrade_available</code> and <code>next_step</code> from
<code>GET /v1/clients/me</code>. To upgrade, run
<code>agrid update --email you@example.com</code>, then <code>agrid verify &lt;code&gt;</code>.</p>

<h2>Registration details</h2>
<pre>pip install theoc-agentgrid-protocol
agrid register --email you@example.com
agrid verify 123456          # code emailed to you; first handoff runs automatically
agrid doctor</pre>
<p><code>agrid register</code> is open self-service — no invite token or operator approval —
but <code>--email</code> is required. We send a single-use 6-digit code that expires in 15
minutes; <code>agrid verify</code> confirms it and only then creates your <code>agk_...</code>
key under <code>~/.agentgrid/credentials.json</code> without printing it. Until then the
account has no usable key. If the code expires, run <code>agrid resend</code> (one code per
60 seconds). The same email is used to recover a mistyped Client ID on a payment form.
Use <code>agrid login</code> if you already have a key, or set
<code>AGENTGRID_API_KEY</code> in the environment.</p>

<h2>Your first verified handoff</h2>
<pre>from agentgrid_protocol import AgentGrid

ag = AgentGrid()
planner = ag.create_agent("Planner", capabilities=["plan"])
worker  = ag.create_agent("Worker", capabilities=["read"])

print(ag.verify_card(planner.agent_id))
receipt = planner.handoff_to(worker, task="summarize the quarterly report")
print(receipt["handoff_id"], len(worker.receipts()))</pre>
<p>The private key for each agent is generated locally and never sent to the service.
Only the public key is registered. The handoff signature covers canonical JSON, and
AgentGrid checks it against the from-agent's registered key before storing a receipt.</p>

<h2 id="scope-design">How scoped delegation works</h2>
<p>Every handoff is a canonical JSON payload signed by the <strong>from-agent's local
Ed25519 key</strong>. It includes <code>v</code>, <code>handoff_id</code>, both agent IDs,
<code>task_hash</code>, <code>scope</code>, <code>created_at</code>, and
<code>parent_handoff_id</code>. AgentGrid verifies that signature against the registered
public key before it stores anything.</p>
<p>For nested delegation, <code>parent_handoff_id</code> must point to a handoff whose
<code>to_agent_id</code> is the agent now delegating. An agent cannot invent a parent
chain to claim permissions it never received.</p>
<p>The enforcement model is deliberately small. Only two scope keys are checked:</p>
<table><thead><tr><th>Scope key</th><th>Rule for a child handoff</th></tr></thead><tbody>
<tr><td><code>allowed</code></td><td>Must be a subset of the parent's <code>allowed</code> list.</td></tr>
<tr><td><code>max_actions</code></td><td>Must be less than or equal to the parent's value.</td></tr>
</tbody></table>
<p>Other keys you put in <code>scope</code> are signed and stored verbatim but are not
constrained. A child may omit either key; the service accepts that and stores only what you
sent. Attempts to widen a chain are rejected with HTTP 400
<code>Delegation scope may not be widened.</code> See the
<a href="#scoped-handoff">scoped handoff recipe</a> for a working parent/child example.</p>

<h2 id="receipt-design">What a receipt records</h2>
<p>Receipts are public by agent ID and immutable at the database level.
<code>GET /v1/agents/{id}/receipts</code> returns the newest handoffs where the agent was
either the sender or the receiver (up to 100 per call).</p>
<table><thead><tr><th>Field</th><th>Meaning</th></tr></thead><tbody>
<tr><td><code>handoff_id</code></td><td>Unique ID of the signed delegation.</td></tr>
<tr><td><code>from_agent_id</code> / <code>to_agent_id</code></td><td>Sender and receiver.</td></tr>
<tr><td><code>parent_handoff_id</code></td><td>The handoff this one narrows, if any.</td></tr>
<tr><td><code>task_hash</code></td><td>SHA-256 of the task text; the raw text is never stored.</td></tr>
<tr><td><code>scope</code></td><td>The signed permission scope.</td></tr>
<tr><td><code>signature</code> / <code>signer_public_key</code></td><td>Ed25519 signature and the from-agent's raw public key, in unpadded base64url.</td></tr>
<tr><td><code>created_at</code></td><td>UTC timestamp covered by the signature.</td></tr>
</tbody></table>
<p>A receipt proves three things: the from-agent's key signed that exact payload, the
signer public key identifies which registered agent signed it, and <code>task_hash</code>
lets you confirm the task you think was delegated without the service storing the text.
It does not prove that the task completed, that the text was confidential, or that a human
was involved. Treat the hash as an integrity check, not a secret. In the snippet below,
<code>task_text</code> is the string you originally passed to <code>handoff_to()</code> on your
own machine.</p>
<pre>import hashlib
from agentgrid_protocol import AgentGrid, canonical
from agentgrid_protocol.crypto import b64d
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ag = AgentGrid()                       # no auth needed for public reads
r = ag.receipts("ag_...")["receipts"][0]

# 1. Compare a task you still hold locally with the stored hash.
print(hashlib.sha256(task_text.encode("utf-8")).hexdigest() == r["task_hash"])

# 2. Verify the handoff signature offline.
payload = {
    "v": 1,
    "handoff_id": r["handoff_id"],
    "from_agent_id": r["from_agent_id"],
    "to_agent_id": r["to_agent_id"],
    "task_hash": r["task_hash"],
    "scope": r["scope"],
    "created_at": r["created_at"],
    "parent_handoff_id": r["parent_handoff_id"] or "",
}
Ed25519PublicKey.from_public_bytes(b64d(r["signer_public_key"])).verify(
    b64d(r["signature"]), canonical(payload)
)
print("handoff signature: VALID")</pre>
<p>Rebuild the payload with <code>"v": 1</code> even though the stored receipt does not expose
that field; it was part of the signed envelope. CLI equivalent:
<code>agrid receipts &lt;agent_id&gt;</code>.</p>

<h2 id="recipes">Copy-paste recipes</h2>

<h3 id="offline-verify">Verify a card offline</h3>
<pre>from agentgrid_protocol import AgentGrid, canonical, unsigned_card
from agentgrid_protocol.crypto import b64d
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ag = AgentGrid()                  # no auth needed for public reads
card = ag.card("ag_...")          # any public agent ID
keys = ag.public_keys()           # includes previous_public_key during rotation
message = canonical(unsigned_card(card))
signature = b64d(card["signature"])

for key_b64 in (keys.get("public_key", ""), keys.get("previous_public_key", "")):
    if not key_b64:
        continue
    try:
        Ed25519PublicKey.from_public_bytes(b64d(key_b64)).verify(signature, message)
        print("offline signature: VALID")
        break
    except Exception:
        continue
else:
    print("offline signature: INVALID")</pre>
<p>A card signature proves AgentGrid issued that card. Handoffs are signed separately by the
from-agent's own local Ed25519 key. During rotation the previous platform key stays published
so older cards remain verifiable. CLI equivalent: <code>agrid card &lt;agent_id&gt;</code>.</p>

<h3 id="scoped-handoff">Record a scoped handoff</h3>
<pre>from agentgrid_protocol import AgentGrid

ag = AgentGrid()
planner = ag.create_agent("Planner", capabilities=["plan"])
worker = ag.create_agent("Worker", capabilities=["read"])

receipt = planner.handoff_to(
    worker,
    task="summarize the quarterly report",
    scope={"allowed": ["read"], "max_actions": 2},
)
print(receipt["handoff_id"], receipt["scope"])

# A child handoff may only narrow the parent's scope:
sub = ag.create_agent("Sub-worker", capabilities=["read"])
child = worker.handoff_to(
    sub,
    task="fetch one page",
    scope={"allowed": ["read"], "max_actions": 1},
    parent_handoff_id=receipt["handoff_id"],
)
print(child["handoff_id"])</pre>
<p><code>allowed</code> must be a subset of the parent's <code>allowed</code>, and
<code>max_actions</code> cannot increase — attempts to widen a chain are rejected. Only a
SHA-256 task hash is stored, never the raw task text.</p>

<h3 id="receipt-read">Read a receipt</h3>
<pre>from agentgrid_protocol import AgentGrid

ag = AgentGrid()
data = ag.receipts("ag_...")       # public: no API key needed
for r in data["receipts"]:
    print(r["handoff_id"], r["from_agent_id"], "-&gt;", r["to_agent_id"])
    print("  task hash:", r["task_hash"])
    print("  scope:", r["scope"], "created:", r["created_at"])
print("total:", data["count"])</pre>
<p>Receipts are immutable at the database level and readable by anyone who knows the agent ID.
They contain the task hash, not the raw task. CLI equivalent:
<code>agrid receipts &lt;agent_id&gt;</code>.</p>

<h2>Useful endpoints</h2>
<table><thead><tr><th>Method</th><th>Path</th><th>Purpose</th></tr></thead><tbody>
<tr><td>POST</td><td><code>/v1/clients/register</code></td><td>Register a free client (open self-service) with a required email</td></tr>
<tr><td>GET</td><td><code>/v1/clients/me</code></td><td>Account status, including the legacy-account upgrade signal</td></tr>
<tr><td>PATCH</td><td><code>/v1/clients/me/email</code></td><td>Set or update the recovery email</td></tr>
<tr><td>POST</td><td><code>/v1/clients/me/upgrade-email</code></td><td>Start self-service email verification for a pre-email account</td></tr>
<tr><td>POST</td><td><code>/v1/agents</code></td><td>Create an agent with its public key</td></tr>
<tr><td>GET</td><td><code>/v1/agents/{id}.json</code></td><td>Get the signed Agent Card</td></tr>
<tr><td>GET</td><td><code>/v1/agents/{id}/verify</code></td><td>Online signature check</td></tr>
<tr><td>GET</td><td><code>/v1/agents/public-key</code></td><td>Platform key for offline checks</td></tr>
<tr><td>POST</td><td><code>/v1/agents/{id}/handoffs</code></td><td>Record a signed handoff</td></tr>
<tr><td>GET</td><td><code>/v1/agents/{id}/receipts</code></td><td>Read immutable receipts</td></tr>
<tr><td>GET</td><td><code>/v1/billing/statement</code></td><td>Invoice, overage, and hard caps</td></tr>
</tbody></table>
<p>Full request and response schemas are in the <a href="/docs">API reference</a>.</p>

<h2>Limits and billing</h2>
<p>Every tier permits overage up to 3× its included agents and handoffs; beyond that, new
agents and handoffs return HTTP 402 until the next cycle or an upgrade. Overage is
$1 per 1,000 extra handoffs plus $0.10 per extra agent per day, written to an immutable
ledger. <code>GET /v1/billing/statement</code> returns an <code>invoice_id</code> and the
amount due in USD. To upgrade, register first with the email you will use to pay,
get your Client ID, then open the payment link for your tier and enter that exact
<strong>AgentGrid Client ID</strong> in the form's required field. Use the same email on
the payment form so we can fix a mistyped Client ID automatically. Your tier upgrades
automatically once payment is confirmed. The invoice ID is
only for operator reconciliation; no payment details ever enter AgentGrid.</p>
<p>Enterprise uses the shared <a href="https://payments.cashfree.com/forms/agentgrid-enterprise" target="_blank" rel="noopener">self-service form</a>;
enter an amount between ₹212,500 and ₹425,000 ($2,500–$5,000 at the fixed ₹85 = $1 rate)
and the same AgentGrid Client ID.</p>

<h2 id="faq">FAQ</h2>
<p class="muted">These are the questions new users hit most often. If yours is not here, tell us — this list grows from real feedback.</p>

<h3>Do I need an invite token or approval?</h3>
<p>No. <code>agrid register</code> is open self-service. You do need a real email: a 6-digit
code is sent there and the API key is created only after you confirm it.</p>

<h3>I signed up before email verification. How do I update?</h3>
<p>If your client has a key but no email on file, run
<code>agrid update --email you@example.com</code> with that key still saved locally.
We email a 6-digit code and your current key stops working until you confirm it.
Then run <code>agrid verify &lt;code&gt;</code>: it stores a replacement key and runs
your first signed handoff automatically. If you lost the old key, register a new
free client instead.</p>

<h3>Does email verification prove I am human?</h3>
<p>It proves you control the inbox at signup, which blocks random bot signups and makes every
account reachable. It is not a biometric or CAPTCHA-style proof. Unverified signups have no
key and cannot call the API.</p>

<h3>Where is my API key? The CLI did not print it.</h3>
<p>By design. The service shows the <code>agk_...</code> key once and the CLI writes it to
<code>~/.agentgrid/credentials.json</code>. Back up that file or the key; there is no secret
recovery endpoint. If you lose it, register a new free client.</p>

<h3>What does <code>agrid quickstart</code> actually do?</h3>
<p>It creates two agents with locally generated Ed25519 keys, verifies the planner's card
online and offline, signs a real handoff with a scope, and reads the resulting receipt. Nothing
is simulated. Private keys never leave your machine.</p>

<h3>Why verify a card "offline"?</h3>
<p>Because the platform's public key is published at
<a href="/v1/agents/public-key"><code>/v1/agents/public-key</code></a>. You can check a card's
signature without asking AgentGrid, which matters when the service is unreachable or when a
third party receives a card. See the <a href="#offline-verify">recipe</a>.</p>

<h3>Can a child agent widen the scope it inherited?</h3>
<p>No. A child's <code>allowed</code> list must be a subset of its parent's and its
<code>max_actions</code> cannot be higher. See the <a href="#scoped-handoff">recipe</a>.</p>

<h3>Are receipts public? Is my task text exposed?</h3>
<p>Receipts are public by agent ID — anyone with the ID can read them. They store a SHA-256
task hash, not the raw task. Treat the hash as an integrity check, not a secret, and do not put
sensitive text in the task field.</p>

<h3>Do I need a payment method to start?</h3>
<p>No. The free tier needs no card. Payments are entirely external; AgentGrid has no wallet,
escrow, checkout, or automatic deduction. See <a href="/">pricing</a>.</p>

<h3>What happens when I hit the free limits?</h3>
<p>Overage is metered (not blocked) up to 3× the included agents and handoffs, at $1 per 1,000
extra handoffs plus $0.10 per extra agent per day. Past 3×, new writes return HTTP 402 until
the next cycle or an upgrade. <code>agrid statement</code> shows the current totals.</p>

<h3>How do I upgrade, and how do I change my email?</h3>
<p>Register with the email you will pay with, get your Client ID, open the external payment
link for your tier, and enter that exact Client ID in the form. The same email lets the operator
fix a mistyped ID. To change it later, call
<code>PATCH /v1/clients/me/email</code> with your API key.</p>

<h3>Can I use a language other than Python?</h3>
<p>Yes. AgentGrid is an HTTP API; the Python SDK is optional. Start from
<a href="/openapi.json">OpenAPI</a> or the <a href="/docs">API reference</a>.</p>

<p><a href="/docs">API reference</a> &middot; <a href="/openapi.json">OpenAPI</a> &middot;
<a href="/health/ready">Health</a></p>
</body></html>"""


OPS_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>AgentGrid · Operator Live</title>
<style>
:root{color-scheme:dark;--bg:#080d1a;--panel:#111a30;--line:#223056;--text:#eaf0ff;--muted:#9db0d0;--accent:#7ee7c7;--warn:#ffcc66;--bad:#ff7b7b}
*{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;background:radial-gradient(900px 500px at 15% -10%,#16305a 0%,transparent 60%),var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--accent)}
.wrap{max-width:1140px;margin:0 auto;padding:28px 20px 64px}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:18px;flex-wrap:wrap}
.brand{font-weight:800;font-size:20px;letter-spacing:.2px}
.brand span{color:var(--accent)}
.kicker{color:var(--muted);font-size:13px;margin-top:3px}
.pill{border:1px solid var(--line);border-radius:999px;padding:6px 12px;font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase}
.pill.on{color:var(--accent);border-color:#2c6c5b;background:#0f2b26}
.pill.off{color:var(--muted);background:#121a30}
.card{background:linear-gradient(180deg,#121c34,#0e1629);border:1px solid var(--line);border-radius:14px;padding:20px;margin-top:18px;box-shadow:0 16px 40px rgba(0,0,0,.22)}
h1{font-size:26px;margin:0 0 8px}
h2{font-size:18px;margin:0 0 6px}
.muted{color:var(--muted)}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin-top:18px}
label{display:block;font-size:13px;color:var(--muted);font-weight:600}
input[type=password],input[type=text]{width:100%;margin-top:7px;padding:11px 12px;border-radius:9px;border:1px solid var(--line);background:#0a1122;color:var(--text);font:inherit}
input[type=password]:focus,input[type=text]:focus{outline:2px solid #2c6c5b;outline-offset:1px}
.row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:16px}
.row.small{font-size:13px;margin-top:0}
button{border:1px solid var(--line);background:#16223e;color:var(--text);border-radius:9px;padding:9px 13px;font:inherit;font-weight:650;cursor:pointer}
button:hover{border-color:#3a5588}
button.primary{background:var(--accent);color:#062018;border-color:var(--accent)}
button.ghost{background:transparent}
.err{color:var(--bad);font-size:13px}
.bar{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;padding:14px 18px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--accent);margin-right:7px;box-shadow:0 0 0 4px rgba(126,231,199,.12)}
.dot.paused{background:var(--warn);box-shadow:0 0 0 4px rgba(255,204,102,.12)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-top:18px}
.stat{background:linear-gradient(180deg,#121c34,#0e1629);border:1px solid var(--line);border-radius:13px;padding:16px}
.stat-label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em;font-weight:700}
.stat-value{font-size:28px;font-weight:800;margin:7px 0 2px;word-break:break-word}
.stat-hint{color:var(--muted);font-size:12px}
.legend{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}
.badge{display:inline-block;border-radius:999px;padding:4px 9px;font-size:12px;font-weight:700;white-space:nowrap}
.badge.ok{background:#0f2b26;color:var(--accent);border:1px solid #2c6c5b}
.badge.warn{background:#332812;color:var(--warn);border:1px solid #6b5524}
.badge.bad{background:#33161c;color:var(--bad);border:1px solid #6b2c36}
.check{display:flex;align-items:center;gap:8px;color:var(--muted);font-weight:500;margin-bottom:12px}
.check input{width:auto;margin:0}
table{width:100%;border-collapse:collapse;font-size:13px;min-width:860px}
th,td{text-align:left;padding:10px 9px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em}
tbody tr:hover{background:#121c34}
code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#cfe0ff}
footer{color:var(--muted);font-size:12px;margin-top:22px}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div>
      <div class="brand">TheoC Computations <span>&middot; AgentGrid</span></div>
      <div class="kicker">Operator live view &middot; read-only &middot; no secrets in page source</div>
    </div>
    <div id="status" class="pill off">Locked</div>
  </div>

  <section id="login" class="card">
    <h1>Live operator console</h1>
    <p class="muted">Sign in with your admin key and current authenticator code. They are exchanged for a 12-hour, read-only browser session. Credentials are cleared from the form immediately and never appear in this page source.</p>
    <div class="grid2">
      <label>Admin key<input id="admin-key" type="password" autocomplete="off" placeholder="X-AgentGrid-Admin-Key value"></label>
      <label>Current TOTP<input id="mfa" type="text" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="6 digits"></label>
    </div>
    <div class="row">
      <button id="unlock" class="primary">Unlock live view</button>
      <span id="login-error" class="err"></span>
    </div>
  </section>

  <main id="dashboard" hidden>
    <section class="card bar">
      <div><span id="live-dot" class="dot"></span><strong id="live-text">Live &middot; auto-refresh 30s</strong></div>
      <div class="row small">
        <span id="updated" class="muted">Not loaded yet</span>
        <button id="refresh">Refresh now</button>
        <button id="toggle">Pause</button>
        <button id="signout" class="ghost">Sign out</button>
      </div>
    </section>

    <section class="cards" id="cards"></section>

    <section class="card">
      <h2>Signup authenticity signals</h2>
      <p class="muted">Email confirmation proves inbox control. Real usage &mdash; creating an agent or signing a handoff &mdash; is the stronger signal. No email-only system can prove personhood, so these are signals, not verdicts.</p>
      <div class="legend">
        <span class="badge ok">Active user</span>
        <span class="badge warn">Verified &middot; no activity yet</span>
        <span class="badge warn">Pending verification</span>
        <span class="badge bad">Disposable-looking email</span>
        <span class="badge bad">Legacy &middot; no email</span>
      </div>
      <label class="check"><input id="include-tests" type="checkbox"> Include operator/test accounts</label>
      <div style="overflow:auto">
        <table>
          <thead><tr><th>Client ID</th><th>Created</th><th>Email</th><th>Verified</th><th>Agents</th><th>Handoffs</th><th>Last activity</th><th>Signal</th></tr></thead>
          <tbody id="rows"></tbody>
        </table>
      </div>
    </section>

    <footer>Source of truth: <code>/v1/admin/stats</code> and <code>/v1/admin/clients</code>. Public totals exclude operator/test prefixes.</footer>
  </main>
</div>
<script>
const el = (id) => document.getElementById(id);
const state = {stats:null, clients:[], timer:null, paused:false, includeTests:false};

function setStatus(text, ok) {
  const s = el('status');
  s.textContent = text;
  s.className = 'pill ' + (ok ? 'on' : 'off');
}

function showLogin(message) {
  el('dashboard').hidden = true;
  el('login').hidden = false;
  setStatus('Locked', false);
  if (message) el('login-error').textContent = message;
}

function showDashboard() {
  el('login').hidden = true;
  el('dashboard').hidden = false;
  el('login-error').textContent = '';
  setStatus('Unlocked', true);
}

function fmt(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

async function call(path, options) {
  const res = await fetch(path, Object.assign({credentials:'include'}, options || {}));
  if (res.status === 401) {
    showLogin('Session expired. Sign in again.');
    throw new Error('unauthorized');
  }
  if (!res.ok) throw new Error((await res.text()).slice(0, 200));
  return res.json();
}

function statCard(label, value, hint) {
  const box = document.createElement('div');
  box.className = 'stat';
  const l = document.createElement('div'); l.className = 'stat-label'; l.textContent = label;
  const v = document.createElement('div'); v.className = 'stat-value'; v.textContent = value;
  const h = document.createElement('div'); h.className = 'stat-hint'; h.textContent = hint || '';
  box.append(l, v, h);
  return box;
}

function signalBadge(signal) {
  const badge = document.createElement('span');
  const map = {
    active_user: ['Active user', 'ok'],
    verified_inactive: ['Verified · no activity yet', 'warn'],
    pending_verification: ['Pending verification', 'warn'],
    disposable_email: ['Disposable-looking email', 'bad'],
    legacy_uncontactable: ['Legacy · no email', 'bad']
  };
  const item = map[signal] || [signal || 'Unknown', 'bad'];
  badge.className = 'badge ' + item[1];
  badge.textContent = item[0];
  return badge;
}

function renderCards() {
  const s = state.stats;
  if (!s) return;
  const p = s.public_users;
  el('cards').replaceChildren(
    statCard('Verified public users', p.total, 'Confirmed inbox control'),
    statCard('Active public users', p.active_users, 'Created an agent or handoff'),
    statCard('Pending verification', s.unverified_signups, 'No API key issued yet'),
    statCard('Agents', p.agents, 'Owned by public users'),
    statCard('Handoffs', p.handoffs, 'Signed by public users'),
    statCard('Paid active', p.paid_active, 'Non-free tier, unexpired'),
    statCard('Newest signup', fmt(p.newest_signup), 'Most recent verified public client'),
    statCard('Test accounts excluded', s.test_accounts_excluded, 'Operator prefixes')
  );
  el('updated').textContent = 'Updated ' + new Date(s.generated_at).toLocaleTimeString();
}

function renderTable() {
  const body = el('rows');
  body.replaceChildren();
  const rows = state.clients.filter((c) => state.includeTests || !c.is_test_account);
  for (const c of rows) {
    const tr = document.createElement('tr');
    const id = document.createElement('td');
    id.textContent = c.client_id.length > 18 ? c.client_id.slice(0, 16) + '…' : c.client_id;
    id.title = c.client_id;
    const created = document.createElement('td'); created.textContent = fmt(c.created_at);
    const email = document.createElement('td'); email.textContent = c.email || '—';
    const verified = document.createElement('td'); verified.textContent = c.email_verified ? 'Verified' : 'Pending';
    const agents = document.createElement('td'); agents.textContent = c.agent_count;
    const handoffs = document.createElement('td'); handoffs.textContent = c.handoff_count;
    const last = document.createElement('td'); last.textContent = fmt(c.last_activity_at);
    const signal = document.createElement('td'); signal.append(signalBadge(c.signal));
    tr.append(id, created, email, verified, agents, handoffs, last, signal);
    body.append(tr);
  }
  if (!rows.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 8; td.className = 'muted'; td.textContent = 'No signups match this view.';
    tr.append(td); body.append(tr);
  }
}

async function load() {
  try {
    const results = await Promise.all([
      call('/v1/admin/stats'),
      call('/v1/admin/clients?limit=200')
    ]);
    state.stats = results[0];
    state.clients = results[1].clients || [];
    renderCards();
    renderTable();
    el('live-text').textContent = state.paused ? 'Paused' : 'Live · auto-refresh 30s';
    el('live-dot').className = 'dot' + (state.paused ? ' paused' : '');
  } catch (e) {
    if (e.message !== 'unauthorized') el('updated').textContent = 'Refresh failed: ' + e.message;
  }
}

function schedule() {
  clearInterval(state.timer);
  if (!state.paused) state.timer = setInterval(load, 30000);
}

el('unlock').onclick = async () => {
  el('login-error').textContent = '';
  try {
    const res = await fetch('/v1/admin/session', {
      method: 'POST',
      credentials: 'include',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({admin_key: el('admin-key').value, mfa: el('mfa').value})
    });
    if (!res.ok) {
      let message = 'Sign-in failed';
      try { message = (await res.json()).detail || message; } catch (e) {}
      el('login-error').textContent = message;
      return;
    }
    el('admin-key').value = '';
    el('mfa').value = '';
    showDashboard();
    await load();
    schedule();
  } catch (e) {
    el('login-error').textContent = 'Network error';
  }
};

el('refresh').onclick = load;
el('toggle').onclick = () => {
  state.paused = !state.paused;
  el('toggle').textContent = state.paused ? 'Resume' : 'Pause';
  schedule();
  load();
};
el('include-tests').onchange = (e) => {
  state.includeTests = e.target.checked;
  renderTable();
};
el('signout').onclick = async () => {
  await fetch('/v1/admin/session/logout', {method: 'POST', credentials: 'include'});
  clearInterval(state.timer);
  state.stats = null;
  state.clients = [];
  showLogin('Signed out.');
};

fetch('/v1/admin/stats', {credentials: 'include'})
  .then((res) => { if (res.ok) { showDashboard(); load(); schedule(); } })
  .catch(() => {});
</script>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    return LANDING_HTML


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt() -> str:
    return (
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /ops\n"
        "Disallow: /ops-lite\n"
        "Disallow: /v1/admin/\n"
        "Disallow: /health/\n"
        "\n"
        f"Sitemap: {PUBLIC_BASE_URL}/sitemap.xml\n"
    )


def _google_verification_tokens() -> set[str]:
    return {
        value.strip()
        for value in os.environ.get("AGENTGRID_GOOGLE_VERIFICATION_TOKENS", "").split(",")
        if value.strip()
    }


@app.get("/google{token}.html", include_in_schema=False)
async def google_site_verification(token: str) -> PlainTextResponse:
    """Serve only the exact Google ownership-verification file we configured.

    Google flags sites that generate a valid verification file for arbitrary
    tokens as hacked, so this route is an explicit allowlist from a private Vercel
    environment variable. No token is stored in the repo or shared in chat.
    """
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", token):
        raise HTTPException(status_code=404, detail="Not Found")
    if token not in _google_verification_tokens():
        raise HTTPException(status_code=404, detail="Not Found")
    return PlainTextResponse(
        f"google-site-verification: google{token}.html",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/sitemap.xml", response_class=PlainTextResponse)
async def sitemap_xml(db: AsyncSession = Depends(get_db)) -> str:
    """Static public pages plus discoverable active agent cards."""
    today = date.today().isoformat()
    static_paths = [
        ("/", "1.0", "weekly"),
        ("/quickstart", "0.9", "weekly"),
        ("/guide", "0.9", "weekly"),
        ("/docs", "0.7", "monthly"),
        ("/openapi.json", "0.5", "monthly"),
    ]
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]
    for path, priority, changefreq in static_paths:
        lines.append(
            "  <url><loc>"
            + html.escape(PUBLIC_BASE_URL + path, quote=True)
            + "</loc><lastmod>"
            + today
            + "</lastmod><changefreq>"
            + changefreq
            + "</changefreq><priority>"
            + priority
            + "</priority></url>"
        )

    result = await db.execute(
        select(AgentModel.agent_id, AgentModel.created_at)
        .where(AgentModel.status == "ACTIVE")
        .order_by(AgentModel.created_at.desc())
        .limit(1000)
    )
    for agent_id, created_at in result.all():
        lastmod = str(created_at or today)[:10]
        loc = PUBLIC_BASE_URL + "/a/" + quote(str(agent_id), safe="")
        lines.append(
            "  <url><loc>"
            + html.escape(loc, quote=True)
            + "</loc><lastmod>"
            + html.escape(lastmod, quote=True)
            + "</lastmod><changefreq>monthly</changefreq><priority>0.6</priority></url>"
        )
    lines.append("</urlset>")
    return "\n".join(lines) + "\n"


@app.get("/ops", response_class=HTMLResponse)
async def operator_live_page() -> HTMLResponse:
    return HTMLResponse(OPS_HTML, headers={"X-Robots-Tag": "noindex, nofollow"})


@app.get("/guide", response_class=HTMLResponse)
async def developer_guide() -> str:
    return GUIDE_HTML


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------
VERIFICATION_TTL_MINUTES = 15
MAX_VERIFICATION_ATTEMPTS = 5


def _verification_secret() -> bytes:
    return (
        os.environ.get("AGENTGRID_SIGNING_KEY_B64")
        or ADMIN_KEY
        or "agentgrid-development"
    ).encode("utf-8")


def _hash_verification_code(client_id: str, code: str) -> str:
    return hmac.new(
        _verification_secret(), f"{client_id}:{code}".encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _new_client_record(
    client_id: str, email: str | None = None, *, require_verification: bool = False
) -> tuple[ClientModel, Optional[str], Optional[str]]:
    """Create a client row. Public signups get no usable key until verified."""
    raw_key = None if require_verification else "agk_" + secrets.token_urlsafe(32)
    # Unverified rows still need a unique api_key_hash; this value is random and
    # never returned, so it cannot authenticate anyone.
    key_hash = hash_api_key(raw_key or "agk_" + secrets.token_urlsafe(32))
    code = f"{secrets.randbelow(1_000_000):06d}" if require_verification else None
    now = datetime.now(timezone.utc)
    today = now.date()
    client = ClientModel(
        client_id=client_id,
        api_key_hash=key_hash,
        email=(email or "").strip().lower() or None,
        email_verified=not require_verification,
        verification_code_hash=_hash_verification_code(client_id, code) if code else None,
        verification_expires_at=(now + timedelta(minutes=VERIFICATION_TTL_MINUTES)).isoformat() if code else None,
        verification_sent_at=now.isoformat() if code else None,
        verification_attempts=0,
        tier="free",
        handoffs_used=0,
        period_month=today.strftime("%Y-%m"),
        cycle_start=today.isoformat(),
        cycle_end=_next_cycle_date(today).isoformat(),
        cycle_tier="free",
        access_expires_at=None,
        created_at=_now_iso(),
    )
    return client, raw_key, code


async def _create_client_db(
    db: AsyncSession,
    client_id: str,
    *,
    audit_action: str,
    email: str | None = None,
    require_verification: bool = False,
) -> dict[str, Any]:
    existing = await db.get(ClientModel, client_id)
    if existing:
        raise HTTPException(status_code=409, detail="Client ID already registered.")
    client, raw_key, code = _new_client_record(
        client_id, email, require_verification=require_verification
    )
    db.add(client)
    record_audit(db, client_id=client_id, action=audit_action, target_type="client", target_id=client_id)
    await db.commit()
    result: dict[str, Any] = {
        "client_id": client_id,
        "tier": "free",
        "limits": TIER_LIMITS["free"],
        "cycle_start": client.cycle_start,
        "cycle_end": client.cycle_end,
    }
    if raw_key:
        result["api_key"] = raw_key
        result["message"] = "Store the API key now; it is shown only once."
    else:
        result["verification_required"] = True
        result["email"] = client.email
        result["message"] = (
            "Check your inbox for a 6-digit code, then run `agrid verify <code>` "
            "or POST /v1/clients/verify-email. No API key exists until then."
        )
    if code:
        # Internal only; the endpoint removes this before returning.
        result["_verification_code"] = code
        # Local/dev convenience only; production never exposes the code in a response.
        if APP_ENV != "production":
            result["verification_code"] = code
    return result


@app.post("/v1/clients/register", status_code=status.HTTP_201_CREATED)
async def register_client(
    payload: RegisterClientRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Open self-service registration for the free tier, with email verification.

    Anyone can register; there is no invite token to distribute. A real email
    is required and a 6-digit code is sent to it. No API key exists until the
    code is confirmed, so unverified signups cannot use the service.
    """
    client_id = payload.client_id or "cli_" + uuid.uuid4().hex
    result = await _create_client_db(
        db,
        client_id,
        audit_action="client.registered",
        email=payload.email,
        require_verification=True,
    )
    code = result.pop("_verification_code", "")
    await send_verification_email(payload.email, client_id, code, str(request.base_url))
    return result


def _code_expired(value: Optional[str]) -> bool:
    expires = _parse_iso(value)
    if not expires:
        return True
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires <= datetime.now(timezone.utc)


def _verification_pending_response(client: ClientModel) -> dict[str, Any]:
    return {
        "client_id": client.client_id,
        "email": client.email,
        "verification_required": True,
        "message": (
            "Check your inbox for a 6-digit code, then run `agrid verify <code>` "
            "or POST /v1/clients/verify-email. No API key exists until then."
        ),
    }


@app.post("/v1/clients/verify-email")
async def verify_email(
    payload: VerifyEmailRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Confirm inbox control, then create and return the client's first API key.

    Only a 6-digit code sent to the registered email can move a public signup
    out of the unverified state. Codes are stored hashed, expire after 15
    minutes, and allow at most five wrong attempts before a resend is needed.
    """
    result = await db.execute(_client_stmt(payload.client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found.")
    if client.email_verified:
        raise HTTPException(status_code=409, detail="Email already verified.")
    if not client.verification_code_hash:
        raise HTTPException(status_code=400, detail="No code pending. Run `agrid resend`.")
    if _code_expired(client.verification_expires_at):
        raise HTTPException(status_code=410, detail="Verification code expired. Run `agrid resend`.")
    if (client.verification_attempts or 0) >= MAX_VERIFICATION_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail="Too many wrong codes. Run `agrid resend` to get a new one.",
        )

    candidate = _hash_verification_code(client.client_id, payload.code)
    if not hmac.compare_digest(candidate, client.verification_code_hash):
        client.verification_attempts = (client.verification_attempts or 0) + 1
        await db.commit()
        remaining = max(0, MAX_VERIFICATION_ATTEMPTS - client.verification_attempts)
        raise HTTPException(
            status_code=400,
            detail=f"Invalid code. {remaining} attempt(s) remaining.",
        )

    raw_key = "agk_" + secrets.token_urlsafe(32)
    client.api_key_hash = hash_api_key(raw_key)
    client.email_verified = True
    client.verification_code_hash = None
    client.verification_expires_at = None
    client.verification_sent_at = None
    client.verification_attempts = 0
    record_audit(
        db,
        client_id=client.client_id,
        action="client.email_verified",
        target_type="client",
        target_id=client.client_id,
        metadata={"email": client.email},
    )
    await db.commit()
    await send_welcome_email(client.email or "", client.client_id, str(request.base_url))
    return {
        "client_id": client.client_id,
        "email_verified": True,
        "api_key": raw_key,
        "tier": active_tier(client),
        "limits": TIER_LIMITS[active_tier(client)],
        "cycle_start": client.cycle_start,
        "cycle_end": client.cycle_end,
        "message": "Email verified. Store this API key now; it is shown only once.",
    }


RESEND_COOLDOWN_SECONDS = 60


@app.post("/v1/clients/resend-verification")
async def resend_verification(
    payload: ResendVerificationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Issue a fresh 6-digit code after the cooldown, resetting wrong attempts."""
    result = await db.execute(_client_stmt(payload.client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found.")
    if client.email_verified:
        raise HTTPException(status_code=409, detail="Email already verified.")

    now = datetime.now(timezone.utc)
    sent = _parse_iso(client.verification_sent_at)
    if sent:
        if sent.tzinfo is None:
            sent = sent.replace(tzinfo=timezone.utc)
        if (now - sent).total_seconds() < RESEND_COOLDOWN_SECONDS:
            raise HTTPException(
                status_code=429,
                detail=f"Please wait {RESEND_COOLDOWN_SECONDS} seconds before requesting another code.",
            )
    if not client.email:
        raise HTTPException(status_code=400, detail="No email on file for this client.")

    code = f"{secrets.randbelow(1_000_000):06d}"
    client.verification_code_hash = _hash_verification_code(client.client_id, code)
    client.verification_expires_at = (now + timedelta(minutes=VERIFICATION_TTL_MINUTES)).isoformat()
    client.verification_sent_at = now.isoformat()
    client.verification_attempts = 0
    record_audit(
        db,
        client_id=client.client_id,
        action="client.verification_resent",
        target_type="client",
        target_id=client.client_id,
        metadata={"email": client.email},
    )
    await db.commit()

    response = _verification_pending_response(client)
    if APP_ENV != "production":
        response["verification_code"] = code
    await send_verification_email(client.email, client.client_id, code, str(request.base_url))
    return response


# ---------------------------------------------------------------------------
# No-code quickstart: email -> code -> real signed handoff, all in the browser.
# ---------------------------------------------------------------------------
QUICKSTART_STYLE = """
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#08101f;color:#eaf0ff;font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:820px;margin:0 auto;padding:34px 20px 70px}
h1{margin:0 0 .3rem;font-size:2rem}
h2{margin:2rem 0 .7rem;border-bottom:1px solid #243456;padding-bottom:.35rem}
a{color:#7ee7c7}
.muted{color:#9db0d0}
.card{background:#111c34;border:1px solid #243456;border-radius:12px;padding:18px 20px;margin:16px 0}
label{display:block;margin:14px 0 5px;font-weight:600}
input{width:100%;max-width:420px;padding:11px 12px;border-radius:8px;border:1px solid #2c3d63;background:#0d172b;color:#eaf0ff;font-size:16px}
button{margin-top:16px;padding:11px 18px;border:0;border-radius:8px;background:#7ee7c7;color:#08101f;font-weight:700;cursor:pointer}
code{background:#15213c;padding:2px 6px;border-radius:5px;word-break:break-all}
.error{background:#40202a;border:1px solid #a3445d;color:#ffd9e1;border-radius:8px;padding:10px 14px;margin:14px 0}
.note{background:#16243f;border:1px solid #2c3d63;border-radius:8px;padding:10px 14px;margin:14px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:18px 0}
.stat .n{font-size:1.5rem;font-weight:700;color:#7ee7c7}
.stat .l{font-size:.85rem;color:#9db0d0}
details{margin-top:14px}
</style>
"""


def _quickstart_headers() -> dict[str, str]:
    return {"Cache-Control": "no-store"}


def _quickstart_shell(title: str, body: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="Get a signed AgentGrid handoff and receipt without writing code.">
<title>{html.escape(title)}</title>{QUICKSTART_STYLE}</head><body><div class="wrap">{body}</div></body></html>"""


def _quickstart_start_html(error: str = "") -> str:
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
    return _quickstart_shell(
        "AgentGrid · No-code quickstart",
        f"""
<p><a href="/">&larr; Home</a> · <a href="/guide">Developer guide</a></p>
<h1>Your first signed handoff, no code needed</h1>
<p class="muted">Enter a real email address. We send a 6-digit code; nothing is created without it.</p>
{error_html}
<div class="card">
<form method="post" action="/v1/quickstart/start">
<label for="email">Email address</label>
<input id="email" name="email" type="email" autocomplete="email" required maxlength="320">
<button type="submit">Send verification code</button>
</form>
</div>
<div class="note"><strong>What happens next?</strong> After you confirm the code, AgentGrid creates
two demo agents, signs a scoped handoff, and shows the receipt. No wallet, card, or API key is
needed for this demo. For production use, the CLI/SDK keeps private keys on your own machine.</div>
""",
    )


def _quickstart_code_html(
    client_id: str, error: str = "", notice: str = "", *, api_key: str = ""
) -> str:
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
    notice_html = f'<div class="note">{html.escape(notice)}</div>' if notice else ""
    key_html = ""
    if api_key:
        key_html = (
            "<details><summary>API key from verification (only if you plan to use the CLI/SDK)</summary>"
            f"<p><code>{html.escape(api_key)}</code></p>"
            "<p class='muted'>Store it privately. It is shown only once.</p></details>"
        )
    safe_id = html.escape(client_id, quote=True)
    return _quickstart_shell(
        "AgentGrid · Check your inbox",
        f"""
<p><a href="/quickstart">&larr; Start over</a></p>
<h1>Check your inbox</h1>
<p class="muted">Client ID: <code>{safe_id}</code></p>
{error_html}{notice_html}
<div class="card">
<form method="post" action="/v1/quickstart/finish">
<input type="hidden" name="client_id" value="{safe_id}">
<label for="code">6-digit code</label>
<input id="code" name="code" inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6" minlength="6" autocomplete="one-time-code" required>
<button type="submit">Verify and create my handoff</button>
</form>
<form method="post" action="/v1/quickstart/resend">
<input type="hidden" name="client_id" value="{safe_id}">
<button type="submit">Resend code</button>
</form>
</div>
{key_html}
""",
    )


def _quickstat(label: str, value: Any) -> str:
    return (
        f'<div class="card stat"><div class="n">{html.escape(str(value))}</div>'
        f'<div class="l">{html.escape(label)}</div></div>'
    )


def _quickstart_done_html(result: dict[str, Any]) -> str:
    planner = html.escape(str(result["planner_id"]))
    worker = html.escape(str(result["worker_id"]))
    handoff = html.escape(str(result["handoff_id"]))
    client_id = html.escape(str(result["client_id"]))
    card_url = html.escape(str(result["card_url"]), quote=True)
    receipts_url = html.escape(str(result["receipts_url"]), quote=True)
    api_key = html.escape(str(result.get("api_key", "")), quote=True)
    quickstart_url = html.escape(PUBLIC_BASE_URL + "/quickstart", quote=True)
    key_html = (
        f"<details><summary>API key for CLI/SDK use (optional)</summary><p><code>{api_key}</code></p>"
        "<p class='muted'>Store it privately. It is shown only once.</p></details>"
    ) if api_key else ""
    return _quickstart_shell(
        "AgentGrid · Handoff created",
        f"""
<p><a href="/quickstart">&larr; Run another demo</a> · <a href="/guide">Developer guide</a></p>
<h1>Your handoff is recorded</h1>
<p class="muted">Client ID: <code>{client_id}</code></p>
<div class="grid">
{_quickstat("Agents created", 2)}
{_quickstat("Signed handoffs", 1)}
{_quickstat("Receipts", result.get("receipt_count", 1))}
</div>
<div class="card">
<p><strong>Planner:</strong> <code>{planner}</code></p>
<p><strong>Worker:</strong> <code>{worker}</code></p>
<p><strong>Handoff:</strong> <code>{handoff}</code></p>
<p><a href="{card_url}">Open the signed Agent Card</a> &middot;
<a href="{receipts_url}">Read the immutable receipt JSON</a></p>
</div>
<div class="card">
<p><strong>Shareable receipt link:</strong> <a href="{receipts_url}">{receipts_url}</a></p>
<p class="muted">Anyone with this link can verify the signature and scope without an API key.</p>
</div>
<p><strong>Know another builder?</strong> Send them <code>{quickstart_url}</code> — they can get their
own signed receipt in under a minute, with no code.</p>
<div class="note">This no-code demo generates demo keys on the server and discards them immediately.
For real deployments, use <code>agrid</code> or the Python SDK so private keys never leave your machine.</div>
{key_html}
""",
    )


async def _quickstart_form_fields(request: Request) -> dict[str, str]:
    body = (await request.body()).decode("utf-8", errors="replace")
    return dict(parse_qsl(body, keep_blank_values=True))


async def _run_quickstart_demo(db: AsyncSession, client_id: str) -> dict[str, Any]:
    """Create two agents, one signed handoff, and read the receipt.

    The demo keys are generated here and discarded; production users keep their
    own private keys via the CLI/SDK.
    """
    planner_private = Ed25519PrivateKey.generate()
    worker_private = Ed25519PrivateKey.generate()
    planner_public = _public_b64(planner_private)
    worker_public = _public_b64(worker_private)

    planner = await create_agent(
        CreateAgentRequest(
            name="Planner",
            description="No-code demo planner",
            capabilities=["plan"],
            public_key=planner_public,
        ),
        client_id=client_id,
        db=db,
    )
    worker = await create_agent(
        CreateAgentRequest(
            name="Worker",
            description="No-code demo worker",
            capabilities=["read"],
            public_key=worker_public,
        ),
        client_id=client_id,
        db=db,
    )

    handoff_id = "h_" + uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    task_hash = hashlib.sha256(b"summarize the quarterly report").hexdigest()
    scope = {"allowed": ["read"], "max_actions": 2}
    signed_payload = {
        "v": 1,
        "handoff_id": handoff_id,
        "from_agent_id": planner["agent_id"],
        "to_agent_id": worker["agent_id"],
        "task_hash": task_hash,
        "scope": scope,
        "created_at": created_at,
        "parent_handoff_id": "",
    }
    signature = _b64e(planner_private.sign(canonical_bytes(signed_payload)))
    handoff = await create_handoff(
        planner["agent_id"],
        CreateHandoffRequest(
            handoff_id=handoff_id,
            to_agent_id=worker["agent_id"],
            task_hash=task_hash,
            scope=scope,
            created_at=created_at,
            signature=signature,
        ),
        client_id=client_id,
        db=db,
    )
    receipts = await get_receipts(worker["agent_id"], 10, db)
    return {
        "planner_id": planner["agent_id"],
        "worker_id": worker["agent_id"],
        "handoff_id": handoff["handoff_id"],
        "receipt_count": receipts["count"],
        "card_url": PUBLIC_BASE_URL + "/a/" + quote(planner["agent_id"], safe=""),
        "receipts_url": PUBLIC_BASE_URL + "/v1/agents/" + quote(worker["agent_id"], safe="") + "/receipts",
    }


@app.get("/quickstart", response_class=HTMLResponse)
async def quickstart_page() -> HTMLResponse:
    return HTMLResponse(_quickstart_start_html(), headers=_quickstart_headers())


@app.post("/v1/quickstart/start", response_class=HTMLResponse)
async def quickstart_start(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    fields = await _quickstart_form_fields(request)
    try:
        payload = RegisterClientRequest(email=fields.get("email", ""))
    except ValidationError:
        return HTMLResponse(
            _quickstart_start_html("Enter a valid email address so we can send your code."),
            status_code=422,
            headers=_quickstart_headers(),
        )
    try:
        result = await register_client(payload, request, db)
    except HTTPException as exc:
        return HTMLResponse(
            _quickstart_start_html(str(exc.detail)),
            status_code=exc.status_code,
            headers=_quickstart_headers(),
        )
    result.pop("verification_code", None)
    return HTMLResponse(
        _quickstart_code_html(
            str(result["client_id"]),
            notice="Code sent. Check your inbox, then paste the 6-digit code below.",
        ),
        headers=_quickstart_headers(),
    )


@app.post("/v1/quickstart/finish", response_class=HTMLResponse)
async def quickstart_finish(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    fields = await _quickstart_form_fields(request)
    client_id = fields.get("client_id", "")
    code = fields.get("code", "")
    try:
        verification = await verify_email(
            VerifyEmailRequest(client_id=client_id, code=code), request, db
        )
    except ValidationError:
        return HTMLResponse(
            _quickstart_code_html(client_id, error="Enter the exact 6-digit code from your inbox."),
            status_code=422,
            headers=_quickstart_headers(),
        )
    except HTTPException as exc:
        return HTMLResponse(
            _quickstart_code_html(client_id, error=str(exc.detail)),
            status_code=exc.status_code,
            headers=_quickstart_headers(),
        )

    api_key = str(verification.get("api_key", ""))
    try:
        demo = await _run_quickstart_demo(db, client_id)
    except HTTPException as exc:
        return HTMLResponse(
            _quickstart_code_html(
                client_id,
                error=f"Email verified, but the demo could not run: {exc.detail}",
                api_key=api_key,
            ),
            status_code=exc.status_code,
            headers=_quickstart_headers(),
        )
    demo["client_id"] = client_id
    demo["api_key"] = api_key
    return HTMLResponse(_quickstart_done_html(demo), headers=_quickstart_headers())


@app.post("/v1/quickstart/resend", response_class=HTMLResponse)
async def quickstart_resend(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    fields = await _quickstart_form_fields(request)
    client_id = fields.get("client_id", "")
    try:
        result = await resend_verification(
            ResendVerificationRequest(client_id=client_id), request, db
        )
    except ValidationError:
        return HTMLResponse(
            _quickstart_code_html(client_id, error="Invalid client ID."),
            status_code=422,
            headers=_quickstart_headers(),
        )
    except HTTPException as exc:
        return HTMLResponse(
            _quickstart_code_html(client_id, error=str(exc.detail)),
            status_code=exc.status_code,
            headers=_quickstart_headers(),
        )
    result.pop("verification_code", None)
    return HTMLResponse(
        _quickstart_code_html(client_id, notice="A fresh code has been sent."),
        headers=_quickstart_headers(),
    )


@app.post("/v1/admin/clients/register", status_code=status.HTTP_201_CREATED)
async def admin_register_client(
    payload: RegisterClientRequest,
    request: Request,
    authorized: bool = Depends(verify_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Operator-assisted onboarding without sharing the registration token.

    Requires the admin key and a valid TOTP code; in production, missing admin
    MFA configuration fails closed. The returned API key is shown only once.
    """
    client_id = payload.client_id or "cli_" + uuid.uuid4().hex
    result = await _create_client_db(
        db, client_id, audit_action="client.registered_by_admin", email=payload.email
    )
    await send_welcome_email(payload.email, client_id, str(request.base_url))
    return result


@app.get("/v1/clients/me")
async def get_my_client(
    client_id: str = Depends(verify_api_key),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    client = await db.get(ClientModel, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found.")
    await ensure_current_period(client, db)
    await db.commit()
    tier = active_tier(client)
    cycle_tier = client.cycle_tier or tier
    legacy_upgrade = bool(client.email_verified and not client.email)
    return {
        "client_id": client.client_id,
        "tier": tier,
        "cycle_tier": cycle_tier,
        "limits": TIER_LIMITS[tier],
        "handoff_hard_cap": TIER_LIMITS[cycle_tier]["handoffs"] * HARD_CAP_MULTIPLIER,
        "handoffs_used": client.handoffs_used,
        "cycle_start": client.cycle_start,
        "cycle_end": client.cycle_end,
        "access_expires_at": client.access_expires_at,
        "prices_usd": TIER_PRICES_USD,
        "email_on_file": bool(client.email),
        "legacy_upgrade_available": legacy_upgrade,
        "next_step": (
            "Run `agrid update --email you@example.com` then `agrid verify <code>` "
            "to add email verification to this pre-email account."
        ) if legacy_upgrade else None,
    }


@app.patch("/v1/clients/me/email")
async def update_my_email(
    payload: UpdateEmailRequest,
    client_id: str = Depends(verify_api_key),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Set the email used to recover a payment if the form Client ID is wrong."""
    client = await db.get(ClientModel, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found.")
    client.email = payload.email.strip().lower()
    await db.commit()
    return {"client_id": client_id, "email": client.email}


@app.post("/v1/clients/me/upgrade-email")
async def upgrade_legacy_email(
    payload: UpdateEmailRequest,
    request: Request,
    client_id: str = Depends(verify_api_key),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Attach an email to a legacy account and start inbox verification.

    Accounts created before email verification had a key issued immediately and
    were backfilled as verified, but have no email on file. The existing key
    proves ownership of the client here. After this call the old key stops
    working until the emailed code is confirmed with ``/v1/clients/verify-email``,
    which issues a replacement key.
    """
    client = await db.get(ClientModel, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found.")
    if client.email:
        raise HTTPException(
            status_code=409,
            detail="This client already has an email. Use PATCH /v1/clients/me/email to change it.",
        )
    if not client.email_verified:
        raise HTTPException(
            status_code=409,
            detail="This client is already pending verification. Run `agrid resend` or `agrid verify <code>`.",
        )

    now = datetime.now(timezone.utc)
    sent = _parse_iso(client.verification_sent_at)
    if sent:
        if sent.tzinfo is None:
            sent = sent.replace(tzinfo=timezone.utc)
        if (now - sent).total_seconds() < RESEND_COOLDOWN_SECONDS:
            raise HTTPException(
                status_code=429,
                detail=f"Please wait {RESEND_COOLDOWN_SECONDS} seconds before requesting another code.",
            )

    email = payload.email.strip().lower()
    code = f"{secrets.randbelow(1_000_000):06d}"
    client.email = email
    client.email_verified = False
    client.verification_code_hash = _hash_verification_code(client_id, code)
    client.verification_expires_at = (now + timedelta(minutes=VERIFICATION_TTL_MINUTES)).isoformat()
    client.verification_sent_at = now.isoformat()
    client.verification_attempts = 0
    record_audit(
        db,
        client_id=client_id,
        action="client.email_upgrade_started",
        target_type="client",
        target_id=client_id,
        metadata={"email": email},
    )
    await db.commit()

    response = _verification_pending_response(client)
    response["legacy_upgrade"] = True
    response["message"] = (
        "Email saved. Check your inbox for a 6-digit code, then run "
        "`agrid verify <code>`. Your current key is replaced at that point; "
        "keep it until verification finishes."
    )
    if APP_ENV != "production":
        response["verification_code"] = code
    await send_verification_email(email, client_id, code, str(request.base_url))
    return response


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------
@app.post("/v1/agents", status_code=status.HTTP_201_CREATED)
async def create_agent(
    payload: CreateAgentRequest,
    client_id: str = Depends(verify_api_key),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    client = await db.get(ClientModel, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found.")
    await ensure_current_period(client, db)
    cycle_tier = client.cycle_tier or active_tier(client)
    included = TIER_LIMITS[cycle_tier]["agents"]
    hard_cap = included * HARD_CAP_MULTIPLIER
    count_result = await db.execute(
        select(AgentModel).where(AgentModel.client_id == client_id, AgentModel.status == "ACTIVE")
    )
    active_count = len(count_result.scalars().all())
    if active_count >= hard_cap:
        await db.commit()
        raise HTTPException(
            status_code=402,
            detail=f"Agent hard cap ({hard_cap}) reached for {cycle_tier} tier.",
        )
    is_overage = active_count >= included
    try:
        public = Ed25519PublicKey.from_public_bytes(_b64d(payload.public_key))
        public_bytes = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except (ValueError, TypeError, binascii.Error):
        raise HTTPException(status_code=422, detail="public_key must be a base64url-encoded 32-byte Ed25519 public key.") from None
    for capability in payload.capabilities:
        if not capability.strip() or len(capability) > 100:
            raise HTTPException(status_code=422, detail="Each capability must be a non-empty string of at most 100 characters.")
    endpoint_url = (payload.endpoint_url or "").strip() or None
    if endpoint_url and (len(endpoint_url) > 500 or not URL_PATTERN.fullmatch(endpoint_url)):
        raise HTTPException(status_code=422, detail="endpoint_url must be a valid http(s) URL or omitted.")
    agent = AgentModel(
        agent_id="ag_" + uuid.uuid4().hex,
        client_id=client_id,
        name=payload.name.strip(),
        description=(payload.description or "").strip() or None,
        capabilities_json=json.dumps(payload.capabilities, separators=(",", ":")),
        endpoint_url=endpoint_url,
        public_key_b64=_b64e(public_bytes),
        status="ACTIVE",
        card_signature_b64="",
        is_overage=is_overage,
        created_at=_now_iso(),
    )
    agent.card_signature_b64 = sign_platform(agent_card(agent))
    db.add(agent)
    if is_overage:
        db.add(
            OverageLedgerModel(
                client_id=client_id,
                cycle_start=client.cycle_start,
                cycle_end=client.cycle_end,
                usage_type="agent",
                units=1,
                unit_price_microdollars=OVERAGE_AGENT_DAY_MICRODOLLARS,
                tier=cycle_tier,
                reference_id=agent.agent_id,
                created_at=agent.created_at,
            )
        )
    record_audit(
        db,
        client_id=client_id,
        action="agent.created",
        target_type="agent",
        target_id=agent.agent_id,
        metadata={"overage": is_overage},
    )
    await db.commit()
    result = signed_card(agent)
    result["overage"] = is_overage
    return result


@app.get("/v1/agents")
async def list_agents(
    client_id: str = Depends(verify_api_key),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    result = await db.execute(select(AgentModel).where(AgentModel.client_id == client_id))
    agents = result.scalars().all()
    return {"agents": [signed_card(agent) for agent in agents], "count": len(agents)}


@app.get("/v1/agents/public-key")
async def public_key() -> dict[str, Any]:
    result: dict[str, Any] = {
        "public_key": PLATFORM_PUBLIC_B64,
        "algorithm": "Ed25519",
        "encoding": "base64url-raw",
    }
    if PREVIOUS_PLATFORM_PRIVATE:
        result["previous_public_key"] = _public_b64(PREVIOUS_PLATFORM_PRIVATE)
    return result


@app.get("/v1/agents/{agent_id}.json")
async def get_agent_card_json(agent_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    agent = await db.get(AgentModel, agent_id)
    if not agent or agent.status != "ACTIVE":
        raise HTTPException(status_code=404, detail="Agent not found.")
    return signed_card(agent)


@app.get("/v1/agents/{agent_id}/verify")
async def verify_agent_card(agent_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    agent = await db.get(AgentModel, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    card = agent_card(agent)
    signature = agent.card_signature_b64 or sign_platform(card)
    return {
        "agent_id": agent_id,
        "signature_valid": verify_platform(card, signature),
        "status": agent.status,
        "public_key": PLATFORM_PUBLIC_B64,
        "signature": signature,
    }


@app.get("/a/{agent_id}", response_class=HTMLResponse)
async def agent_card_page(agent_id: str, db: AsyncSession = Depends(get_db)) -> str:
    agent = await db.get(AgentModel, agent_id)
    if not agent:
        return "<h1>Agent not found</h1>"
    card = signed_card(agent)
    capabilities = ", ".join(html.escape(str(cap)) for cap in card["capabilities"]) or "none declared"
    card_url = PUBLIC_BASE_URL + "/a/" + quote(agent_id, safe="")
    card_description = (
        str(card.get("description") or "").strip()
        or f"Signed AgentGrid card for {card['name']} with offline-verifiable identity and capabilities."
    )
    card_structured_data: dict[str, Any] = {
        "@context": "https://schema.org",
        "@graph": [
            {
                "@type": "WebPage",
                "@id": card_url + "#webpage",
                "url": card_url,
                "name": str(card["name"]) + " — AgentGrid signed card",
                "description": card_description,
                "isPartOf": {"@id": PUBLIC_BASE_URL + "/#website"},
            },
            {
                "@type": "SoftwareApplication",
                "@id": card_url + "#agent",
                "name": str(card["name"]),
                "description": card_description,
                "applicationCategory": "DeveloperApplication",
                "identifier": str(card["agent_id"]),
                "url": card_url,
                "publisher": {"@id": PUBLIC_BASE_URL + "/#organization"},
            },
        ],
    }
    seo = _seo_meta(
        str(card["name"]) + " — AgentGrid signed agent card",
        card_description,
        "/a/" + quote(agent_id, safe=""),
        structured_data=card_structured_data,
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
{seo}
<style>body{{font:16px system-ui;max-width:720px;margin:8vh auto;padding:24px;background:#0b1020;color:#eef}}
.badge{{color:#7ee7c7}}code{{background:#18213c;padding:2px 6px;border-radius:4px}}</style></head><body>
<p class="badge">AgentGrid verified card</p><h1>{html.escape(card['name'])}</h1>
<p>{html.escape(card['description'] or '')}</p><p><strong>Capabilities:</strong> {capabilities}</p>
<p><strong>Endpoint:</strong> <code>{html.escape(card['endpoint'] or 'not published')}</code></p>
<p><strong>Agent ID:</strong> <code>{html.escape(card['agent_id'])}</code></p>
<p><strong>Public key:</strong> <code>{html.escape(card['public_key'])}</code></p>
<p><strong>Issued:</strong> {html.escape(card['issued_at'])}</p>
<p>Signature: <code>{html.escape(card['signature'])}</code></p>
<p><a href="/v1/agents/{html.escape(agent_id)}/verify">Verify</a> &middot;
<a href="/v1/agents/{html.escape(agent_id)}.json">JSON</a></p>
<p class="badge"><strong>Share this card:</strong> <code>{html.escape(card_url, quote=True)}</code></p>
<p>Want your own signed card and handoff? <a href="/quickstart">Run the no-code quickstart</a> —
no code, CLI, or API key needed.</p></body></html>"""


# ---------------------------------------------------------------------------
# Handoffs
# ---------------------------------------------------------------------------
@app.post("/v1/agents/{from_agent_id}/handoffs", status_code=status.HTTP_201_CREATED)
async def create_handoff(
    from_agent_id: str,
    payload: CreateHandoffRequest,
    client_id: str = Depends(verify_api_key),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    if not HANDOFF_ID_PATTERN.fullmatch(payload.handoff_id):
        raise HTTPException(status_code=422, detail="handoff_id must match h_<32 hex chars>.")
    if not HEX64_PATTERN.fullmatch(payload.task_hash):
        raise HTTPException(status_code=422, detail="task_hash must be a 64-character lowercase hex SHA-256 value.")
    if not _valid_recent_timestamp(payload.created_at):
        raise HTTPException(status_code=422, detail="created_at must be an ISO-8601 UTC timestamp within the allowed clock skew.")
    if not _validate_scope(payload.scope):
        raise HTTPException(status_code=422, detail="scope must be a small JSON object without non-finite numbers.")
    if payload.parent_handoff_id and not HANDOFF_ID_PATTERN.fullmatch(payload.parent_handoff_id):
        raise HTTPException(status_code=422, detail="parent_handoff_id must match h_<32 hex chars>.")
    from_agent = await db.get(AgentModel, from_agent_id)
    to_agent = await db.get(AgentModel, payload.to_agent_id)
    if not from_agent or not to_agent:
        raise HTTPException(status_code=404, detail="Both agents must exist.")
    if from_agent.client_id != client_id:
        raise HTTPException(status_code=403, detail="You may only record handoffs from your own agent.")
    if from_agent.status != "ACTIVE" or to_agent.status != "ACTIVE":
        raise HTTPException(status_code=409, detail="Both agents must be ACTIVE.")

    handoff_payload = {
        "v": 1,
        "handoff_id": payload.handoff_id,
        "from_agent_id": from_agent_id,
        "to_agent_id": payload.to_agent_id,
        "task_hash": payload.task_hash,
        "scope": payload.scope,
        "created_at": payload.created_at,
        "parent_handoff_id": payload.parent_handoff_id or "",
    }
    if not verify_agent_signature(handoff_payload, payload.signature, from_agent.public_key_b64):
        raise HTTPException(status_code=401, detail="Handoff signature is invalid for the from-agent public key.")

    if payload.parent_handoff_id:
        parent = await db.get(HandoffModel, payload.parent_handoff_id)
        if not parent or parent.to_agent_id != from_agent_id:
            raise HTTPException(status_code=400, detail="parent_handoff_id must be a handoff into the from-agent.")
        try:
            parent_scope = json.loads(parent.scope_json)
        except (ValueError, TypeError):
            parent_scope = {}
        if not scope_is_subset(payload.scope, parent_scope):
            raise HTTPException(status_code=400, detail="Delegation scope may not be widened.")

    client = await db.get(ClientModel, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found.")
    await ensure_current_period(client, db)
    cycle_tier = client.cycle_tier or active_tier(client)
    included = TIER_LIMITS[cycle_tier]["handoffs"]
    hard_cap = included * HARD_CAP_MULTIPLIER
    if client.handoffs_used >= hard_cap:
        await db.commit()
        raise HTTPException(
            status_code=402,
            detail=f"Handoff hard cap ({hard_cap}) reached for {cycle_tier} tier.",
        )
    is_overage = client.handoffs_used >= included

    handoff = HandoffModel(
        handoff_id=payload.handoff_id,
        client_id=client_id,
        from_agent_id=from_agent_id,
        to_agent_id=payload.to_agent_id,
        parent_handoff_id=payload.parent_handoff_id,
        task_hash=payload.task_hash,
        scope_json=json.dumps(payload.scope, sort_keys=True, separators=(",", ":")),
        signature_b64=payload.signature,
        signer_public_key_b64=from_agent.public_key_b64,
        created_at=payload.created_at,
    )
    db.add(handoff)
    client.handoffs_used += 1
    if is_overage:
        db.add(
            OverageLedgerModel(
                client_id=client_id,
                cycle_start=client.cycle_start,
                cycle_end=client.cycle_end,
                usage_type="handoff",
                units=1,
                unit_price_microdollars=OVERAGE_HANDOFF_MICRODOLLARS,
                tier=cycle_tier,
                reference_id=payload.handoff_id,
                created_at=payload.created_at,
            )
        )
    record_audit(
        db,
        client_id=client_id,
        action="handoff.recorded",
        target_type="handoff",
        target_id=payload.handoff_id,
        metadata={"overage": is_overage},
    )
    try:
        await db.commit()
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Duplicate handoff_id or storage error.") from exc
    return {
        "handoff_id": handoff.handoff_id,
        "from_agent_id": from_agent_id,
        "to_agent_id": payload.to_agent_id,
        "status": "RECORDED",
        "signature_valid": True,
        "overage": is_overage,
        "cycle_end": client.cycle_end,
    }


@app.get("/v1/agents/{agent_id}/receipts")
async def get_receipts(
    agent_id: str,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 100.")
    agent = await db.get(AgentModel, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    result = await db.execute(
        select(HandoffModel)
        .where((HandoffModel.from_agent_id == agent_id) | (HandoffModel.to_agent_id == agent_id))
        .order_by(HandoffModel.created_at.desc())
        .limit(limit)
    )
    receipts = [
        {
            "handoff_id": row.handoff_id,
            "from_agent_id": row.from_agent_id,
            "to_agent_id": row.to_agent_id,
            "parent_handoff_id": row.parent_handoff_id,
            "task_hash": row.task_hash,
            "scope": json.loads(row.scope_json),
            "signature": row.signature_b64,
            "signer_public_key": row.signer_public_key_b64,
            "created_at": row.created_at,
        }
        for row in result.scalars().all()
    ]
    return {"agent_id": agent_id, "receipts": receipts, "count": len(receipts)}


# ---------------------------------------------------------------------------
# Ledger-backed statements (no internal money flow)
# ---------------------------------------------------------------------------
def _invoice_id(client_id: str, cycle_start: str) -> str:
    digest = hashlib.sha256(f"{client_id}:{cycle_start}".encode("utf-8")).hexdigest()[:16]
    return f"inv_{digest}"


async def _statement_totals(
    db: AsyncSession, *, client_id: str, cycle_start: str, cycle_end: str, tier: str
) -> dict[str, Any]:
    result = await db.execute(
        select(OverageLedgerModel).where(
            OverageLedgerModel.client_id == client_id,
            OverageLedgerModel.cycle_start == cycle_start,
        )
    )
    rows = result.scalars().all()

    handoff_count = 0
    agent_rows = []
    for row in rows:
        if row.usage_type == "handoff":
            handoff_count += row.units
        elif row.usage_type == "agent":
            agent_rows.append(row)

    start = _parse_date(cycle_start)
    end = _parse_date(cycle_end)
    agent_days = 0
    if start and end:
        for row in agent_rows:
            created = _parse_date(str(row.created_at)[:10]) or start
            billable_start = max(created, start)
            days = (end - billable_start).days
            agent_days += max(days, 1)

    handoff_micro = handoff_count * OVERAGE_HANDOFF_MICRODOLLARS
    agent_micro = agent_days * OVERAGE_AGENT_DAY_MICRODOLLARS
    overage_micro = handoff_micro + agent_micro
    base_micro = TIER_BASE_MICRODOLLARS.get(tier)
    return {
        "base_microdollars": base_micro,
        "handoff_count": handoff_count,
        "handoff_microdollars": handoff_micro,
        "agent_count": len(agent_rows),
        "agent_days": agent_days,
        "agent_microdollars": agent_micro,
        "overage_microdollars": overage_micro,
        "total_microdollars": (base_micro or 0) + overage_micro,
    }


def _statement_payload(
    *,
    client_id: str,
    cycle_start: str,
    cycle_end: str,
    tier: str,
    totals: dict[str, Any],
    final: bool,
    payment_status: str,
    cashfree_order_id: Optional[str] = None,
) -> dict[str, Any]:
    base_micro = totals["base_microdollars"]
    due_micro = totals["total_microdollars"] if base_micro is not None else totals["overage_microdollars"]
    included = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    return {
        "invoice_id": _invoice_id(client_id, cycle_start),
        "client_id": client_id,
        "cycle_start": cycle_start,
        "cycle_end": cycle_end,
        "tier": tier,
        "final": final,
        "payment_status": payment_status,
        "cashfree_order_id": cashfree_order_id,
        "base_fee_usd": _format_usd(base_micro) if base_micro is not None else None,
        "base_fee_note": None if base_micro is not None else "custom amount agreed manually",
        "overage": {
            "handoffs": {
                "count": totals["handoff_count"],
                "rate": "$1 per 1,000 extra handoffs",
                "amount_usd": _format_usd(totals["handoff_microdollars"]),
            },
            "agents": {
                "extra_agents": totals["agent_count"],
                "agent_days": totals["agent_days"],
                "rate": "$0.10 per extra agent per day",
                "amount_usd": _format_usd(totals["agent_microdollars"]),
            },
        },
        "total_due_usd": _format_usd(due_micro),
        "total_due_microdollars": due_micro,
        "hard_caps": {
            "agents": included["agents"] * HARD_CAP_MULTIPLIER,
            "handoffs": included["handoffs"] * HARD_CAP_MULTIPLIER,
        },
        "payment_instructions": (
            "Pay externally using the operator-provided Cashfree link and quote this invoice_id. "
            "No in-app payment, wallet balance, or automatic deduction is used."
        ),
    }


async def _get_or_create_statement(
    db: AsyncSession, *, client_id: str, cycle_start: str, cycle_end: str, tier: str
) -> BillingStatementModel:
    """Create or refresh an unpaid statement snapshot for a rolling cycle."""
    result = await db.execute(
        select(BillingStatementModel).where(
            BillingStatementModel.client_id == client_id,
            BillingStatementModel.cycle_start == cycle_start,
        )
    )
    statement = result.scalar_one_or_none()
    if not statement:
        totals = await _statement_totals(
            db,
            client_id=client_id,
            cycle_start=cycle_start,
            cycle_end=cycle_end,
            tier=tier,
        )
        statement = BillingStatementModel(
            client_id=client_id,
            cycle_start=cycle_start,
            cycle_end=cycle_end,
            tier=tier,
            amount_microdollars=(
                totals["total_microdollars"]
                if totals["base_microdollars"] is not None
                else totals["overage_microdollars"]
            ),
            payment_status="unpaid",
            created_at=_now_iso(),
        )
        db.add(statement)
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            stored = await db.execute(
                select(BillingStatementModel).where(
                    BillingStatementModel.client_id == client_id,
                    BillingStatementModel.cycle_start == cycle_start,
                )
            )
            statement = stored.scalar_one()
    elif statement.payment_status != "paid":
        totals = await _statement_totals(
            db,
            client_id=client_id,
            cycle_start=cycle_start,
            cycle_end=cycle_end,
            tier=statement.tier,
        )
        statement.amount_microdollars = (
            totals["total_microdollars"]
            if totals["base_microdollars"] is not None
            else totals["overage_microdollars"]
        )
        statement.cycle_end = cycle_end
    return statement


@app.get("/v1/billing/statement")
async def get_statement(
    cycle_start: Optional[str] = None,
    client_id: str = Depends(verify_api_key),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    client = await db.get(ClientModel, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found.")
    await ensure_current_period(client, db)
    await db.commit()

    selected_start = cycle_start or client.cycle_start
    try:
        start = _parse_date(selected_start)
    except ValueError:
        start = None
    if not start:
        raise HTTPException(status_code=422, detail="cycle_start must be YYYY-MM-DD.")
    end = _next_cycle_date(start)
    cycle_end = end.isoformat()
    selected_start = start.isoformat()

    tier = client.cycle_tier or active_tier(client)
    final = datetime.now(timezone.utc).date() >= end
    payment_status = "current"
    cashfree_order_id = None

    if final:
        statement = await _get_or_create_statement(
            db,
            client_id=client_id,
            cycle_start=selected_start,
            cycle_end=cycle_end,
            tier=tier,
        )
        tier = statement.tier
        payment_status = statement.payment_status
        cashfree_order_id = statement.cashfree_order_id
        await db.commit()

    totals = await _statement_totals(
        db,
        client_id=client_id,
        cycle_start=selected_start,
        cycle_end=cycle_end,
        tier=tier,
    )
    return _statement_payload(
        client_id=client_id,
        cycle_start=selected_start,
        cycle_end=cycle_end,
        tier=tier,
        totals=totals,
        final=final,
        payment_status=payment_status,
        cashfree_order_id=cashfree_order_id,
    )


@app.post("/v1/admin/session")
async def create_ops_session(payload: AdminSessionRequest) -> JSONResponse:
    """Exchange admin key + TOTP for a short-lived, read-only /ops cookie."""
    _check_admin_credentials(payload.admin_key, payload.mfa)
    response = JSONResponse(
        {"status": "ok", "scope": "ops:read", "expires_in": OPS_SESSION_TTL_SECONDS}
    )
    response.set_cookie(
        OPS_SESSION_COOKIE,
        _make_ops_session_token(),
        max_age=OPS_SESSION_TTL_SECONDS,
        httponly=True,
        secure=APP_ENV == "production",
        samesite="strict",
        path="/",
    )
    return response


@app.post("/v1/admin/session/logout")
async def delete_ops_session() -> JSONResponse:
    response = JSONResponse({"status": "ok"})
    response.delete_cookie(OPS_SESSION_COOKIE, path="/", samesite="strict")
    return response


# ---------------------------------------------------------------------------
# Simple read-only operator view: one read key + catch phrase, no TOTP.
# ---------------------------------------------------------------------------
OPS_LITE_STYLE = """
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#08101f;color:#eaf0ff;font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
h1{margin:0 0 .2rem;font-size:2rem}
h2{margin:2rem 0 .7rem;border-bottom:1px solid #243456;padding-bottom:.35rem}
a{color:#7ee7c7}
.muted{color:#9db0d0}
.card{background:#111c34;border:1px solid #243456;border-radius:12px;padding:16px 18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.stat .n{font-size:1.8rem;font-weight:700;color:#7ee7c7}
.stat .l{font-size:.85rem;color:#9db0d0}
label{display:block;margin:12px 0 4px;font-weight:600}
input{width:100%;max-width:420px;padding:10px 12px;border-radius:8px;border:1px solid #2c3d63;background:#0d172b;color:#eaf0ff}
button{margin-top:16px;padding:10px 16px;border:0;border-radius:8px;background:#7ee7c7;color:#08101f;font-weight:700;cursor:pointer}
.error{background:#40202a;border:1px solid #a3445d;color:#ffd9e1;border-radius:8px;padding:10px 14px;margin:14px 0}
table{width:100%;border-collapse:collapse;margin-top:10px}
th,td{padding:9px 8px;border-bottom:1px solid #243456;text-align:left;vertical-align:top}
th{color:#9db0d0;font-size:.85rem;text-transform:uppercase;letter-spacing:.04em}
code{background:#15213c;padding:2px 6px;border-radius:5px}
.top{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}
</style>
"""


def _lite_esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _ops_lite_headers() -> dict[str, str]:
    return {"X-Robots-Tag": "noindex, nofollow"}


def _ops_lite_shell(title: str, body: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{_lite_esc(title)}</title>{OPS_LITE_STYLE}</head><body><div class="wrap">{body}</div></body></html>"""


def _ops_lite_login_html(error: str = "") -> str:
    error_html = f'<div class="error">{_lite_esc(error)}</div>' if error else ""
    return _ops_lite_shell(
        "AgentGrid · Read-only operator view",
        f"""
<h1>AgentGrid snapshot</h1>
<p class="muted">User counts and recent client details. No TOTP needed for this view.</p>
{error_html}
<div class="card">
<form method="post" action="/v1/ops-lite/session">
<label for="key">Read key</label>
<input id="key" name="key" autocomplete="off" required>
<label for="catch_phrase">Catch phrase</label>
<input id="catch_phrase" name="catch_phrase" autocomplete="off" required>
<button type="submit">Open snapshot</button>
</form>
</div>
<p class="muted">This view is read-only. Admin changes still use the protected console.</p>
""",
    )


def _ops_lite_stat(label: str, value: Any) -> str:
    return f'<div class="card stat"><div class="n">{_lite_esc(value)}</div><div class="l">{_lite_esc(label)}</div></div>'


def _ops_lite_dashboard_html(stats: dict[str, Any], clients: list[dict[str, Any]]) -> str:
    public = stats.get("public_users", {})
    # This view is for real accounts only. Operator/test accounts remain in the
    # database for audit and billing history, but never render here.
    clients = [client for client in clients if not client.get("is_test_account")]
    cards = "".join(
        [
            _ops_lite_stat("Public users", public.get("total", 0)),
            _ops_lite_stat("Verified", public.get("verified", 0)),
            _ops_lite_stat("Pending", stats.get("unverified_signups", 0)),
            _ops_lite_stat("Active users", public.get("active_users", 0)),
            _ops_lite_stat("Paid active", public.get("paid_active", 0)),
            _ops_lite_stat("Agents", public.get("agents", 0)),
            _ops_lite_stat("Handoffs", public.get("handoffs", 0)),
        ]
    )
    rows = []
    for client in clients:
        client_id = _lite_esc(client.get("client_id"))
        rows.append(
            "<tr>"
            f'<td><a href="/ops-lite/client/{client_id}"><code>{client_id}</code></a></td>'
            f'<td>{_lite_esc(client.get("email") or "—")}</td>'
            f'<td>{_lite_esc(client.get("signal"))}</td>'
            f'<td>{_lite_esc(client.get("tier"))}</td>'
            f'<td>{_lite_esc(client.get("agent_count", 0))}</td>'
            f'<td>{_lite_esc(client.get("handoff_count", 0))}</td>'
            f'<td>{_lite_esc(str(client.get("created_at") or "")[:10])}</td>'
            "</tr>"
        )
    table_rows = "".join(rows) or '<tr><td colspan="7" class="muted">No clients yet.</td></tr>'
    generated = _lite_esc(stats.get("generated_at"))
    return _ops_lite_shell(
        "AgentGrid · Snapshot",
        f"""
<div class="top"><div><h1>AgentGrid snapshot</h1>
<p class="muted">Generated {generated}. Read-only.</p></div>
<form method="post" action="/v1/ops-lite/logout"><button type="submit">Sign out</button></form>
</div>
<div class="grid">{cards}</div>
<h2>Recent clients</h2>
<table><thead><tr><th>Client ID</th><th>Email</th><th>Signal</th><th>Tier</th><th>Agents</th><th>Handoffs</th><th>Created</th></tr></thead>
<tbody>{table_rows}</tbody></table>
""",
    )


def _ops_lite_detail_html(detail: dict[str, Any]) -> str:
    usage = detail.get("usage", {})
    events = detail.get("recent_billing_events", [])
    event_rows = "".join(
        "<tr>"
        f'<td>{_lite_esc(event.get("created_at"))}</td>'
        f'<td>{_lite_esc(event.get("action"))}</td>'
        f'<td>{_lite_esc(event.get("tier"))}</td>'
        f'<td>{_lite_esc(event.get("cashfree_order_id") or "—")}</td>'
        "</tr>"
        for event in events
    ) or '<tr><td colspan="4" class="muted">No billing events.</td></tr>'
    return _ops_lite_shell(
        "AgentGrid · Client detail",
        f"""
<p><a href="/ops-lite">← Back to snapshot</a></p>
<h1>{_lite_esc(detail.get("client_id"))}</h1>
<div class="grid">
{_ops_lite_stat("Tier", detail.get("tier"))}
{_ops_lite_stat("Payment", detail.get("payment_status"))}
{_ops_lite_stat("Amount due", detail.get("amount_due_usd"))}
{_ops_lite_stat("Agents", usage.get("agents", 0))}
{_ops_lite_stat("Handoffs", usage.get("handoffs", 0))}
</div>
<p class="muted">Cycle {_lite_esc(detail.get("cycle_start"))} → {_lite_esc(detail.get("cycle_end"))} · Invoice {_lite_esc(detail.get("invoice_id"))}</p>
<h2>Recent billing events</h2>
<table><thead><tr><th>When</th><th>Action</th><th>Tier</th><th>Order</th></tr></thead><tbody>{event_rows}</tbody></table>
""",
    )


@app.post("/v1/ops-lite/session")
async def create_ops_lite_session(request: Request) -> Any:
    fields: dict[str, str] = {}
    if "application/json" in request.headers.get("content-type", "").lower():
        try:
            raw_json = await request.json()
            if isinstance(raw_json, dict):
                fields = {str(k): str(v) for k, v in raw_json.items()}
        except (ValueError, TypeError):
            fields = {}
    else:
        body = (await request.body()).decode("utf-8", errors="replace")
        fields = dict(parse_qsl(body, keep_blank_values=True))
    key = fields.get("key", "")[:256]
    catch_phrase = fields.get("catch_phrase", "")[:256]
    try:
        _check_ops_lite_credentials(key, catch_phrase)
    except HTTPException as exc:
        return HTMLResponse(
            _ops_lite_login_html(str(exc.detail)),
            status_code=exc.status_code,
            headers=_ops_lite_headers(),
        )
    response = RedirectResponse("/ops-lite", status_code=303)
    response.set_cookie(
        OPS_LITE_COOKIE,
        _make_ops_lite_token(),
        max_age=OPS_LITE_TTL_SECONDS,
        httponly=True,
        secure=APP_ENV == "production",
        samesite="none" if APP_ENV == "production" else "lax",
        path="/",
    )
    return response


@app.post("/v1/ops-lite/logout")
async def delete_ops_lite_session() -> RedirectResponse:
    response = RedirectResponse("/ops-lite", status_code=303)
    response.delete_cookie(
        OPS_LITE_COOKIE,
        path="/",
        samesite="none" if APP_ENV == "production" else "lax",
    )
    return response


def _ops_lite_authorized(request: Request) -> bool:
    return _ops_lite_session_valid(
        request.cookies.get(OPS_LITE_COOKIE)
    ) or _ops_session_valid(request.cookies.get(OPS_SESSION_COOKIE))


@app.get("/ops-lite", response_class=HTMLResponse)
async def ops_lite_page(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    if not _ops_lite_authorized(request):
        return HTMLResponse(_ops_lite_login_html(), headers=_ops_lite_headers())
    stats = await admin_stats(limit=5_000, authorized=True, db=db)
    clients = await admin_list_clients(limit=200, authorized=True, db=db)
    return HTMLResponse(
        _ops_lite_dashboard_html(stats, clients.get("clients", [])),
        headers=_ops_lite_headers(),
    )


@app.get("/ops-lite/client/{client_id}", response_class=HTMLResponse)
async def ops_lite_client_page(
    client_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    if not _ops_lite_authorized(request):
        return HTMLResponse(_ops_lite_login_html(), headers=_ops_lite_headers())
    if client_id.startswith(OPERATOR_TEST_PREFIXES):
        body = _ops_lite_shell(
            "AgentGrid · Not found",
            '<p><a href="/ops-lite">← Back to snapshot</a></p><h1>Client not found</h1>',
        )
        return HTMLResponse(body, status_code=404, headers=_ops_lite_headers())
    try:
        detail = await admin_client_status(client_id, authorized=True, db=db)
    except HTTPException as exc:
        body = _ops_lite_shell(
            "AgentGrid · Not found",
            f'<p><a href="/ops-lite">← Back to snapshot</a></p><h1>Client not found</h1><div class="error">{_lite_esc(exc.detail)}</div>',
        )
        return HTMLResponse(body, status_code=exc.status_code, headers=_ops_lite_headers())
    return HTMLResponse(_ops_lite_detail_html(detail), headers=_ops_lite_headers())


def _signup_signal(client: ClientModel, agent_count: int, handoff_count: int) -> str:
    if not client.email_verified:
        return "pending_verification"
    if not client.email:
        return "legacy_uncontactable"
    if _email_is_disposable(client.email):
        return "disposable_email"
    if agent_count or handoff_count:
        return "active_user"
    return "verified_inactive"


@app.get("/v1/admin/clients")
async def admin_list_clients(
    limit: int = 50,
    authorized: bool = Depends(verify_ops_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Read-only overview of recent clients for operator checks and /ops."""
    bounded = max(1, min(limit, 200))
    result = await db.execute(
        select(ClientModel).order_by(ClientModel.created_at.desc()).limit(bounded)
    )
    clients = result.scalars().all()
    ids = [client.client_id for client in clients]

    agent_rows = await db.execute(
        select(AgentModel.client_id, func.count(AgentModel.agent_id), func.max(AgentModel.created_at))
        .where(AgentModel.client_id.in_(ids))
        .group_by(AgentModel.client_id)
    )
    agent_stats = {
        str(client_id): {"count": int(count), "last": last}
        for client_id, count, last in agent_rows.all()
    }
    handoff_rows = await db.execute(
        select(
            HandoffModel.client_id,
            func.count(HandoffModel.handoff_id),
            func.max(HandoffModel.created_at),
        )
        .where(HandoffModel.client_id.in_(ids))
        .group_by(HandoffModel.client_id)
    )
    handoff_stats = {
        str(client_id): {"count": int(count), "last": last}
        for client_id, count, last in handoff_rows.all()
    }

    today = datetime.now(timezone.utc).date()
    items: list[dict[str, Any]] = []
    for client in clients:
        start, end = cycle_bounds(client)
        selected_start = start.isoformat()
        stored = await db.execute(
            select(BillingStatementModel).where(
                BillingStatementModel.client_id == client.client_id,
                BillingStatementModel.cycle_start == selected_start,
            )
        )
        statement = stored.scalar_one_or_none()
        closed = today >= end
        a = agent_stats.get(client.client_id, {"count": 0, "last": None})
        h = handoff_stats.get(client.client_id, {"count": 0, "last": None})
        last_activity = max(
            [value for value in (a["last"], h["last"]) if value], default=None
        )
        items.append(
            {
                "client_id": client.client_id,
                "tier": active_tier(client),
                "tier_on_record": client.tier,
                "cycle_start": selected_start,
                "cycle_end": end.isoformat(),
                "access_expires_at": client.access_expires_at,
                "invoice_id": _invoice_id(client.client_id, selected_start),
                "payment_status": (
                    statement.payment_status if statement and closed
                    else ("current" if not closed else "unpaid")
                ),
                "cashfree_order_id": statement.cashfree_order_id if statement else None,
                "created_at": client.created_at,
                "email": _mask_email(client.email),
                "email_verified": bool(client.email_verified),
                "disposable_email": _email_is_disposable(client.email),
                "verification_attempts": int(client.verification_attempts or 0),
                "agent_count": a["count"],
                "handoff_count": h["count"],
                "last_activity_at": last_activity,
                "is_test_account": client.client_id.startswith(OPERATOR_TEST_PREFIXES),
                "signal": _signup_signal(client, a["count"], h["count"]),
            }
        )
    return {"count": len(items), "clients": items}


@app.get("/v1/admin/stats")
async def admin_stats(
    limit: int = 5_000,
    authorized: bool = Depends(verify_ops_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Aggregate tier and usage counts for a quick operator pulse check."""
    bounded = max(1, min(limit, 10_000))
    result = await db.execute(
        select(ClientModel).order_by(ClientModel.created_at.desc()).limit(bounded)
    )
    clients = result.scalars().all()
    now = datetime.now(timezone.utc)

    agent_rows = await db.execute(
        select(AgentModel.client_id, func.count(AgentModel.agent_id)).group_by(AgentModel.client_id)
    )
    agent_counts = {str(client_id): int(count) for client_id, count in agent_rows.all()}
    handoff_rows = await db.execute(
        select(HandoffModel.client_id, func.count(HandoffModel.handoff_id)).group_by(
            HandoffModel.client_id
        )
    )
    handoff_counts = {str(client_id): int(count) for client_id, count in handoff_rows.all()}

    def summarize(rows: list[ClientModel]) -> dict[str, Any]:
        tiers = {name: 0 for name in TIER_LIMITS}
        paid_active = 0
        agents = 0
        handoffs = 0
        active_users = 0
        ids = set()
        for client in rows:
            ids.add(client.client_id)
            tier = active_tier(client)
            tiers[tier] = tiers.get(tier, 0) + 1
            expiry = _parse_iso(client.access_expires_at)
            if tier != "free" and expiry and expiry >= now:
                paid_active += 1
            a = agent_counts.get(client.client_id, 0)
            h = handoff_counts.get(client.client_id, 0)
            agents += a
            handoffs += h
            if a or h:
                active_users += 1
        return {
            "total": len(rows),
            "verified": sum(1 for client in rows if client.email_verified),
            "tiers": tiers,
            "paid_active": paid_active,
            "agents": agents,
            "handoffs": handoffs,
            "active_users": active_users,
            "newest_signup": rows[0].created_at if rows else None,
        }

    public_clients = [
        client
        for client in clients
        if not client.client_id.startswith(OPERATOR_TEST_PREFIXES)
    ]
    verified_public_clients = [client for client in public_clients if client.email_verified]
    return {
        "generated_at": now.isoformat(),
        "limit": bounded,
        "all_accounts": summarize(clients),
        # Public user counts only include humans who confirmed inbox control.
        "public_users": summarize(verified_public_clients),
        "unverified_signups": len(public_clients) - len(verified_public_clients),
        "test_accounts_excluded": len(clients) - len(public_clients),
        "excluded_prefixes": list(OPERATOR_TEST_PREFIXES),
    }


@app.get("/v1/admin/clients/by-email/{email}")
async def admin_client_by_email(
    email: str,
    authorized: bool = Depends(verify_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Resolve a client from the email used on an external payment form.

    Used only as a recovery path when a customer mistypes the Client ID on the
    payment form. Requires admin key + valid TOTP, like the other admin routes.
    """
    normalized = email.strip().lower()
    if not normalized or len(normalized) > 320:
        raise HTTPException(status_code=422, detail="Invalid email address.")
    result = await db.execute(
        select(ClientModel)
        .where(func.lower(ClientModel.email) == normalized)
        .order_by(ClientModel.created_at.desc())
        .limit(1)
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="No client for that email.")
    return {"client_id": client.client_id, "email": client.email, "tier": client.tier}


@app.get("/v1/admin/clients/{client_id}/status")
async def admin_client_status(
    client_id: str,
    authorized: bool = Depends(verify_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Read-only detail for one client: access, invoice, and recent billing events."""
    client = await db.get(ClientModel, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found.")

    start, end = cycle_bounds(client)
    selected_start = start.isoformat()
    selected_end = end.isoformat()
    closed = datetime.now(timezone.utc).date() >= end
    effective_tier = active_tier(client)
    billing_tier = client.cycle_tier or effective_tier
    totals = await _statement_totals(
        db,
        client_id=client_id,
        cycle_start=selected_start,
        cycle_end=selected_end,
        tier=billing_tier,
    )
    stored = await db.execute(
        select(BillingStatementModel).where(
            BillingStatementModel.client_id == client_id,
            BillingStatementModel.cycle_start == selected_start,
        )
    )
    statement = stored.scalar_one_or_none()
    if statement:
        payment_status = statement.payment_status
        order_id = statement.cashfree_order_id
        payment_id = statement.cashfree_payment_id
        amount_micro = statement.amount_microdollars
    else:
        payment_status = "current" if not closed else "unpaid"
        order_id = None
        payment_id = None
        amount_micro = (
            totals["total_microdollars"]
            if totals["base_microdollars"] is not None
            else totals["overage_microdollars"]
        )

    history = await db.execute(
        select(BillingHistoryModel)
        .where(BillingHistoryModel.client_id == client_id)
        .order_by(BillingHistoryModel.id.desc())
        .limit(10)
    )
    events = [
        {
            "action": row.action,
            "tier": row.tier,
            "cashfree_order_id": row.cashfree_order_id,
            "cashfree_payment_id": row.cashfree_payment_id,
            "created_at": row.created_at,
        }
        for row in history.scalars().all()
    ]
    agent_rows = await db.execute(
        select(AgentModel.agent_id).where(AgentModel.client_id == client_id)
    )
    included = TIER_LIMITS.get(effective_tier, TIER_LIMITS["free"])
    return {
        "client_id": client_id,
        "tier": effective_tier,
        "tier_on_record": client.tier,
        "cycle_tier": client.cycle_tier,
        "access_active": effective_tier != "free",
        "access_expires_at": client.access_expires_at,
        "cycle_start": selected_start,
        "cycle_end": selected_end,
        "cycle_closed": closed,
        "invoice_id": _invoice_id(client_id, selected_start),
        "payment_status": payment_status,
        "cashfree_order_id": order_id,
        "cashfree_payment_id": payment_id,
        "amount_due_usd": _format_usd(amount_micro),
        "usage": {
            "agents": len(agent_rows.scalars().all()),
            "handoffs": client.handoffs_used,
            "hard_caps": {
                "agents": included["agents"] * HARD_CAP_MULTIPLIER,
                "handoffs": included["handoffs"] * HARD_CAP_MULTIPLIER,
            },
        },
        "recent_billing_events": events,
    }


@app.post("/v1/admin/clients/{client_id}/statements/{cycle_start}/record-payment")
async def record_statement_payment(
    client_id: str,
    cycle_start: str,
    payload: RecordStatementPaymentRequest,
    authorized: bool = Depends(verify_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    if not ORDER_ID_PATTERN.fullmatch(payload.cashfree_order_id):
        raise HTTPException(status_code=422, detail="cashfree_order_id contains invalid characters.")
    if payload.cashfree_payment_id and not ORDER_ID_PATTERN.fullmatch(payload.cashfree_payment_id):
        raise HTTPException(status_code=422, detail="cashfree_payment_id contains invalid characters.")
    try:
        start = _parse_date(cycle_start)
    except ValueError:
        start = None
    if not start:
        raise HTTPException(status_code=422, detail="cycle_start must be YYYY-MM-DD.")
    selected_start = start.isoformat()

    client = await db.get(ClientModel, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found.")
    end = _next_cycle_date(start)
    if datetime.now(timezone.utc).date() < end:
        raise HTTPException(status_code=409, detail="This billing cycle is not closed yet.")

    statement = await _get_or_create_statement(
        db,
        client_id=client_id,
        cycle_start=selected_start,
        cycle_end=end.isoformat(),
        tier=client.cycle_tier or active_tier(client),
    )
    await db.commit()

    if statement.payment_status == "paid" and statement.cashfree_order_id != payload.cashfree_order_id:
        raise HTTPException(status_code=409, detail="Statement was already paid with another order.")

    prior = await db.execute(
        select(BillingHistoryModel).where(
            BillingHistoryModel.cashfree_order_id == payload.cashfree_order_id
        )
    )
    prior_payment = prior.scalar_one_or_none()
    if prior_payment:
        if prior_payment.client_id == client_id and f"cycle_start={selected_start}" in prior_payment.details:
            return {
                "duplicate": True,
                "invoice_id": _invoice_id(client_id, selected_start),
                "client_id": client_id,
                "cycle_start": selected_start,
                "payment_status": "paid",
            }
        raise HTTPException(status_code=409, detail="Cashfree order ID was used for another payment.")

    statement.payment_status = "paid"
    statement.cashfree_order_id = payload.cashfree_order_id
    statement.cashfree_payment_id = payload.cashfree_payment_id
    statement.paid_at = _now_iso()
    db.add(
        BillingHistoryModel(
            client_id=client_id,
            action="external_statement_payment",
            cashfree_order_id=payload.cashfree_order_id,
            cashfree_payment_id=payload.cashfree_payment_id,
            tier=statement.tier,
            details=(
                f"cycle_start={selected_start}; cycle_end={statement.cycle_end}; "
                f"amount_microdollars={statement.amount_microdollars}"
            ),
            created_at=_now_iso(),
        )
    )
    record_audit(
        db,
        client_id=client_id,
        action="statement.paid_external",
        target_type="statement",
        target_id=_invoice_id(client_id, selected_start),
        metadata={"tier": statement.tier},
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Cashfree order ID was already used.") from exc

    return {
        "duplicate": False,
        "invoice_id": _invoice_id(client_id, selected_start),
        "client_id": client_id,
        "cycle_start": selected_start,
        "payment_status": "paid",
        "amount_due_usd": _format_usd(statement.amount_microdollars),
    }


# ---------------------------------------------------------------------------
# Admin plan grant (external order verified by operator; base billed at cycle end)
# ---------------------------------------------------------------------------
@app.post("/v1/admin/clients/{client_id}/grant-access")
async def grant_access(
    client_id: str,
    payload: GrantAccessRequest,
    authorized: bool = Depends(verify_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    if not ORDER_ID_PATTERN.fullmatch(payload.cashfree_order_id):
        raise HTTPException(status_code=422, detail="cashfree_order_id contains invalid characters.")
    if payload.cashfree_payment_id and not ORDER_ID_PATTERN.fullmatch(payload.cashfree_payment_id):
        raise HTTPException(status_code=422, detail="cashfree_payment_id contains invalid characters.")
    if payload.grant_reason == "external_payment" and not payload.cashfree_payment_id:
        raise HTTPException(
            status_code=422,
            detail="cashfree_payment_id is required for an external payment grant.",
        )
    if payload.grant_reason != "external_payment" and (
        not payload.reason_note or len(payload.reason_note.strip()) < 3
    ):
        raise HTTPException(
            status_code=422,
            detail="reason_note is required for operator grants.",
        )
    client = await db.get(ClientModel, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found.")
    existing = await db.execute(
        select(BillingHistoryModel).where(BillingHistoryModel.cashfree_order_id == payload.cashfree_order_id)
    )
    prior = existing.scalar_one_or_none()
    if prior:
        if prior.client_id == client_id and prior.tier == payload.tier:
            return {
                "duplicate": True,
                "client_id": client_id,
                "tier": prior.tier,
                "cashfree_order_id": payload.cashfree_order_id,
                "message": "This order already granted this access.",
            }
        raise HTTPException(status_code=409, detail="Cashfree order ID was used for a different grant.")

    await ensure_current_period(client, db)
    client.tier = payload.tier
    client.cycle_tier = payload.tier
    client.access_expires_at = f"{client.cycle_end}T00:00:00Z"
    db.add(
        BillingHistoryModel(
            client_id=client_id,
            action="external_plan_access_grant",
            cashfree_order_id=payload.cashfree_order_id,
            cashfree_payment_id=payload.cashfree_payment_id,
            tier=payload.tier,
            details=(
                f"Plan access granted; source={payload.grant_reason}; tier={payload.tier}; "
                f"order={payload.cashfree_order_id}; "
                f"payment={payload.cashfree_payment_id or 'none'}; "
                f"note={payload.reason_note or 'none'}; "
                f"base and overage billed at cycle end {client.cycle_end}"
            ),
            created_at=_now_iso(),
        )
    )
    record_audit(
        db,
        client_id=client_id,
        action="access.granted_external",
        target_type="client",
        target_id=client_id,
        metadata={
            "tier": payload.tier,
            "cashfree_order_id": payload.cashfree_order_id,
            "grant_source": payload.grant_reason,
        },
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Cashfree order ID was already used for a different grant.") from exc
    return {
        "duplicate": False,
        "client_id": client_id,
        "tier": payload.tier,
        "grant_source": payload.grant_reason,
        "access_expires_at": client.access_expires_at,
        "limits": TIER_LIMITS[payload.tier],
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
