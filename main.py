from fastapi import FastAPI, HTTPException

from zerodha import ZerodhaAuthenticator

app = FastAPI(title="Zerodha Auth Service")


@app.post("/authenticate")
def authenticate():
    """Runs the full login flow in one shot: opens a browser for you to log in,
    captures the redirect, exchanges the token, and saves it to Secrets Manager
    and kite_token.json."""
    auth = ZerodhaAuthenticator()
    try:
        auth.authenticate()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "status": "success",
        "access_token": auth.access_token,
        "saved_to": auth.local_token_file,
    }
