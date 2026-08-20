"""In-memory ephemeral authentication-session tracking.

Bridges the two API calls that make up one broker login: POST .../start
(which runs start_login() and, if the broker asks for a second factor,
parks the open Selenium session here) and POST .../otp (which looks the
session back up by broker name and finishes it with submit_otp()).

Sessions are keyed by broker rather than a session_id handed to the
frontend - the frontend never needs to know a session_id, and it also keeps
"one active authentication per broker" simple to enforce. Nothing here is
persisted: a process restart drops all pending sessions (and orphans their
Chrome processes, which os-level process cleanup handles independently).

Each session carries a hard expiry so an abandoned OTP step (user closes the
tab, walks away, etc.) doesn't leave a headless Chrome process running
forever - it's force-aborted after OTP_WAIT_TIMEOUT even if nobody ever
calls back in.
"""

import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

OTP_WAIT_TIMEOUT = timedelta(minutes=5)


class SessionInProgress(Exception):
    """Raised when a new session is requested for a broker that already has one in progress."""


@dataclass
class PendingSession:
    session_id: str
    broker: str
    authenticator: object
    created_at: datetime
    expires_at: datetime


_lock = threading.Lock()
_pending: dict[str, PendingSession] = {}


def start_session(broker, authenticator):
    """Registers a session awaiting OTP for `broker`. Raises SessionInProgress
    if one is already pending for that broker."""
    with _lock:
        if broker in _pending:
            raise SessionInProgress(
                f'An authentication for "{broker}" is already in progress.'
            )

        now = datetime.now(timezone.utc)
        session = PendingSession(
            session_id=str(uuid.uuid4()),
            broker=broker,
            authenticator=authenticator,
            created_at=now,
            expires_at=now + OTP_WAIT_TIMEOUT,
        )
        _pending[broker] = session

        timer = threading.Timer(
            OTP_WAIT_TIMEOUT.total_seconds(), _expire, args=(broker, session.session_id)
        )
        timer.daemon = True
        timer.start()

    return session


def pop_session(broker):
    """Removes and returns the pending session for `broker`, or None if there
    isn't one (never registered, already consumed, or expired)."""
    with _lock:
        session = _pending.get(broker)
        if session is None:
            return None
        if datetime.now(timezone.utc) > session.expires_at:
            del _pending[broker]
            return None
        del _pending[broker]
        return session


def cancel_session(broker):
    """Like pop_session, but also tears down the authenticator's Selenium
    session. Returns the cancelled session, or None if there wasn't one."""
    session = pop_session(broker)
    if session is not None:
        session.authenticator.abort()
    return session


def _expire(broker, session_id):
    """Timer callback: force-aborts a session that nobody ever submitted an
    OTP for."""
    with _lock:
        session = _pending.get(broker)
        if session is None or session.session_id != session_id:
            return
        del _pending[broker]

    try:
        session.authenticator.abort()
    except Exception:
        pass
