import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from base_authenticator import InvalidCredentials
from zerodha import ZerodhaAuthenticator
from mastertrust import MasterTrustAuthenticator
import session_manager

logger = logging.getLogger("broker_auth")

app = FastAPI(title="Broker Auth Service")

BROKER_REGISTRY = {
    "zerodha": ZerodhaAuthenticator,
    "mastertrust": MasterTrustAuthenticator,
}

FRONTEND_DIR = Path(__file__).resolve().parent / "authentication_application"


class StartAuthRequest(BaseModel):
    user_id: str
    password: str


class SubmitOtpRequest(BaseModel):
    otp: str


def _authenticator_for(broker: str):
    authenticator_cls = BROKER_REGISTRY.get(broker.lower())
    if authenticator_cls is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown broker '{broker}'. Available: {list(BROKER_REGISTRY)}",
        )
    return authenticator_cls


@app.get("/brokers")
def list_brokers():
    """Returns the broker keys the frontend can offer for authentication."""
    return {"brokers": list(BROKER_REGISTRY)}


@app.post("/auth/{broker}/start")
async def start_auth(broker: str, body: StartAuthRequest):
    """Starts a broker login: runs Selenium/Chrome headlessly on the backend
    and submits the given credentials. The credentials and the broker's
    access token are never returned to the frontend - only a status."""
    broker_key = broker.lower()
    authenticator_cls = _authenticator_for(broker_key)
    authenticator = authenticator_cls()

    user_id = body.user_id
    password = body.password
    try:
        try:
            otp_required = await run_in_threadpool(authenticator.start_login, user_id, password)
        except InvalidCredentials:
            logger.info("start_login rejected invalid credentials for broker '%s'", broker_key)
            authenticator.abort()
            raise HTTPException(status_code=401, detail="Invalid broker login credentials.")
        except Exception:
            logger.exception("start_login failed for broker '%s'", broker_key)
            authenticator.abort()
            raise HTTPException(status_code=502, detail="Broker login could not be started.")

        if not otp_required:
            return {"status": "authenticated"}

        try:
            session_manager.start_session(broker_key, authenticator)
        except session_manager.SessionInProgress as exc:
            authenticator.abort()
            raise HTTPException(status_code=409, detail=str(exc))

        return {"status": "otp_required"}
    finally:
        # Drop references to the plaintext credentials now that they've been
        # handed to Selenium; nothing here persists them past this point.
        user_id = None
        password = None
        body.password = None


@app.post("/auth/{broker}/otp")
async def submit_auth_otp(broker: str, body: SubmitOtpRequest):
    """Completes a broker login started by /start, using the OTP the frontend
    just collected. The access token is never returned to the frontend."""
    broker_key = broker.lower()
    _authenticator_for(broker_key)

    session = session_manager.pop_session(broker_key)
    if session is None:
        raise HTTPException(
            status_code=404,
            detail=f'No authentication in progress for "{broker_key}" (or it expired).',
        )

    otp = body.otp
    try:
        try:
            await run_in_threadpool(session.authenticator.submit_otp, otp)
        except Exception:
            logger.exception("submit_otp failed for broker '%s'", broker_key)
            raise HTTPException(status_code=502, detail="OTP submission failed.")

        return {"status": "authenticated"}
    finally:
        otp = None
        body.otp = None


@app.post("/auth/{broker}/cancel")
def cancel_auth(broker: str):
    """Cancels a pending OTP-wait session, if any, and tears down its
    Selenium session."""
    broker_key = broker.lower()
    _authenticator_for(broker_key)

    session = session_manager.cancel_session(broker_key)
    if session is None:
        raise HTTPException(
            status_code=404,
            detail=f'No authentication in progress for "{broker_key}".',
        )
    return {"status": "cancelled"}


# Mounted last so it never shadows the API routes above.
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
