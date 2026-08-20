"""In-memory authentication session tracking.

Supports exactly one active browser session at a time (the EC2 box only has
one Xvfb display / one Chrome / one noVNC feed to show). Session IDs are not
hardcoded anywhere, so a future move to concurrent sessions only requires
changing the "one active session" rule below, not the data model.
"""

import secrets
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

SESSION_TIMEOUT = timedelta(minutes=10)

ACTIVE_STATUSES = {"starting_browser", "waiting_for_otp", "authenticating"}


class SessionStatus(str, Enum):
    STARTING_BROWSER = "starting_browser"
    WAITING_FOR_OTP = "waiting_for_otp"
    AUTHENTICATING = "authenticating"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AuthSession:
    session_id: str
    broker: str
    vnc_token: str
    status: str
    created_at: datetime
    expires_at: datetime
    error: Optional[str] = None
    authenticator: object = field(default=None, repr=False)

    def public_dict(self):
        return {
            "session_id": self.session_id,
            "broker": self.broker,
            "status": self.status,
            "error": self.error,
        }


class SessionInProgress(Exception):
    """Raised when a new session is requested while one is already active."""


_lock = threading.Lock()
_sessions: dict[str, AuthSession] = {}
_active_session_id: Optional[str] = None


def start_session(broker, authenticator_cls):
    global _active_session_id

    with _lock:
        active = _sessions.get(_active_session_id) if _active_session_id else None
        if active and active.status in ACTIVE_STATUSES:
            raise SessionInProgress(
                f'An authentication session for "{active.broker}" is already in progress.'
            )

        now = datetime.now(timezone.utc)
        session = AuthSession(
            session_id=str(uuid.uuid4()),
            broker=broker,
            vnc_token=secrets.token_urlsafe(32),
            status=SessionStatus.STARTING_BROWSER.value,
            created_at=now,
            expires_at=now + SESSION_TIMEOUT,
        )
        _sessions[session.session_id] = session
        _active_session_id = session.session_id

    thread = threading.Thread(
        target=_run_session, args=(session.session_id, authenticator_cls), daemon=True
    )
    thread.start()
    return session


def _run_session(session_id, authenticator_cls):
    global _active_session_id
    session = _sessions[session_id]

    def on_status(status_name):
        with _lock:
            if session.status in ACTIVE_STATUSES:
                session.status = status_name

    try:
        auth = authenticator_cls()
        with _lock:
            session.authenticator = auth
        auth.authenticate(on_status=on_status)
        with _lock:
            session.status = SessionStatus.SUCCESS.value
    except Exception as exc:
        with _lock:
            if session.status != SessionStatus.CANCELLED.value:
                session.status = SessionStatus.FAILED.value
                session.error = str(exc)
    finally:
        with _lock:
            if _active_session_id == session_id:
                _active_session_id = None


def get_session(session_id):
    with _lock:
        return _sessions.get(session_id)


def cancel_session(session_id):
    with _lock:
        session = _sessions.get(session_id)
        if not session or session.status not in ACTIVE_STATUSES:
            return session
        session.status = SessionStatus.CANCELLED.value
        auth = session.authenticator

    if auth:
        auth.cancel()
    return session


def verify_vnc_token(token):
    """Used by the /auth/vnc/verify endpoint that Nginx's auth_request calls."""
    if not token:
        return False
    now = datetime.now(timezone.utc)
    with _lock:
        for session in _sessions.values():
            if (
                secrets.compare_digest(session.vnc_token, token)
                and session.status in ACTIVE_STATUSES
                and now <= session.expires_at
            ):
                return True
    return False
