from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles

from zerodha import ZerodhaAuthenticator
from mastertrust import MasterTrustAuthenticator

app = FastAPI(title="Broker Auth Service")

BROKER_REGISTRY = {
    "zerodha": ZerodhaAuthenticator,
    "mastertrust": MasterTrustAuthenticator,
}

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "authentication_application"


@app.get("/brokers")
def list_brokers():
    """Returns the broker keys the frontend can offer for authentication."""
    return {"brokers": list(BROKER_REGISTRY)}


@app.post("/authenticate/{broker}")
def authenticate(broker: str):
    """Runs the given broker's full login flow in one shot: opens a browser,
    auto-fills credentials where supported, waits for OTP/2FA, captures the
    redirect, exchanges the token, and saves it to Secrets Manager."""
    authenticator_cls = BROKER_REGISTRY.get(broker.lower())
    if authenticator_cls is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown broker '{broker}'. Available: {list(BROKER_REGISTRY)}",
        )

    auth = authenticator_cls()
    try:
        auth.authenticate()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "status": "success",
        "broker": broker.lower(),
        "access_token": auth.access_token,
    }


# Mounted last so it never shadows the API routes above.
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
