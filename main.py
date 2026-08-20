from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles

from zerodha import ZerodhaAuthenticator
from mastertrust import MasterTrustAuthenticator
import session_manager

app = FastAPI(title="Broker Auth Service")

BROKER_REGISTRY = {
    "zerodha": ZerodhaAuthenticator,
    "mastertrust": MasterTrustAuthenticator,
}

FRONTEND_DIR = Path(__file__).resolve().parent / "authentication_application"


@app.get("/brokers")
def list_brokers():
    """Returns the broker keys the frontend can offer for authentication."""
    return {"brokers": list(BROKER_REGISTRY)}


@app.post("/auth/{broker}/start")
def start_auth(broker: str):
    """Starts a broker login session: launches Selenium/Chrome in the background
    (visible through the embedded noVNC viewer) and returns immediately with a
    session_id plus a one-time VNC access token. The broker access token itself
    is never returned by this API - it only ever lands in Secrets Manager."""
    authenticator_cls = BROKER_REGISTRY.get(broker.lower())
    if authenticator_cls is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown broker '{broker}'. Available: {list(BROKER_REGISTRY)}",
        )

    try:
        session = session_manager.start_session(broker.lower(), authenticator_cls)
    except session_manager.SessionInProgress as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    return {
        **session.public_dict(),
        "vnc_token": session.vnc_token,
    }


@app.get("/auth/session/{session_id}")
def get_auth_session(session_id: str):
    """Polled by the frontend to drive the UI's state machine."""
    session = session_manager.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Unknown session_id.")
    return session.public_dict()


@app.post("/auth/session/{session_id}/cancel")
def cancel_auth_session(session_id: str):
    session = session_manager.cancel_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Unknown session_id.")
    return session.public_dict()


@app.get("/auth/vnc/verify")
def verify_vnc(token: str = Query(default="")):
    """Called only by Nginx's auth_request directive, never by the frontend
    directly. Gates the noVNC feed behind the per-session token instead of a
    reusable global VNC password."""
    if not session_manager.verify_vnc_token(token):
        raise HTTPException(status_code=403, detail="Invalid or expired VNC session token.")
    return {"ok": True}


# Mounted last so it never shadows the API routes above.
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
