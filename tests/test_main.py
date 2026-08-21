"""Tests the FastAPI orchestration layer (main.py) against fake broker
authenticators, so these don't depend on real Selenium/AWS. Broker-specific
Selenium login logic is covered separately in test_authenticators.py."""

import pytest
from fastapi.testclient import TestClient

from fakes import make_fake_authenticator_cls

import main
import session_manager


@pytest.fixture(autouse=True)
def reset_pending_sessions():
    session_manager._pending.clear()
    yield
    session_manager._pending.clear()


@pytest.fixture
def client():
    return TestClient(main.app)


def _register(monkeypatch, broker, cls):
    monkeypatch.setattr(main, "BROKER_REGISTRY", {**main.BROKER_REGISTRY, broker: cls})


@pytest.mark.parametrize("broker", ["zerodha", "mastertrust"])
def test_start_auth_reports_otp_required(client, monkeypatch, broker):
    cls = make_fake_authenticator_cls(otp_required=True)
    _register(monkeypatch, broker, cls)

    res = client.post(f"/auth/{broker}/start", json={"user_id": "u1", "password": "p1"})

    assert res.status_code == 200
    assert res.json() == {"status": "otp_required"}
    assert cls.instances[0].seen_password == "p1"


@pytest.mark.parametrize("broker", ["zerodha", "mastertrust"])
def test_start_auth_completes_without_otp(client, monkeypatch, broker):
    cls = make_fake_authenticator_cls(otp_required=False)
    _register(monkeypatch, broker, cls)

    res = client.post(f"/auth/{broker}/start", json={"user_id": "u1", "password": "p1"})

    assert res.status_code == 200
    assert res.json() == {"status": "authenticated"}
    assert "SECRET-TOKEN-SHOULD-NOT-LEAK" not in res.text


@pytest.mark.parametrize("broker", ["zerodha", "mastertrust"])
def test_submit_otp_completes_authentication(client, monkeypatch, broker):
    cls = make_fake_authenticator_cls(otp_required=True)
    _register(monkeypatch, broker, cls)

    client.post(f"/auth/{broker}/start", json={"user_id": "u1", "password": "p1"})
    res = client.post(f"/auth/{broker}/otp", json={"otp": "123456"})

    assert res.status_code == 200
    assert res.json() == {"status": "authenticated"}
    assert "SECRET-TOKEN-SHOULD-NOT-LEAK" not in res.text
    assert cls.instances[0].seen_otp == "123456"


def test_unknown_broker_on_start_is_404(client):
    res = client.post("/auth/unknownbroker/start", json={"user_id": "u1", "password": "p1"})
    assert res.status_code == 404


def test_unknown_broker_on_otp_is_404(client):
    res = client.post("/auth/unknownbroker/otp", json={"otp": "123456"})
    assert res.status_code == 404


def test_start_login_failure_returns_502_and_tears_down(client, monkeypatch):
    cls = make_fake_authenticator_cls(start_raises=True)
    _register(monkeypatch, "zerodha", cls)

    res = client.post("/auth/zerodha/start", json={"user_id": "u1", "password": "p1"})

    assert res.status_code == 502
    assert cls.instances[0].aborted is True
    # a failed start must not leave a pending OTP session behind
    assert session_manager.pop_session("zerodha") is None


def test_start_login_invalid_credentials_returns_401_with_clear_detail(client, monkeypatch):
    cls = make_fake_authenticator_cls(start_raises_invalid_credentials=True)
    _register(monkeypatch, "mastertrust", cls)

    res = client.post("/auth/mastertrust/start", json={"user_id": "u1", "password": "wrong"})

    assert res.status_code == 401
    assert res.json() == {"detail": "Invalid broker login credentials."}
    assert cls.instances[0].aborted is True
    assert session_manager.pop_session("mastertrust") is None


def test_submit_otp_invalid_credentials_returns_401_with_clear_detail(client, monkeypatch):
    cls = make_fake_authenticator_cls(otp_required=True, otp_raises_invalid_credentials=True)
    _register(monkeypatch, "mastertrust", cls)

    client.post("/auth/mastertrust/start", json={"user_id": "u1", "password": "p1"})
    res = client.post("/auth/mastertrust/otp", json={"otp": "000000"})

    assert res.status_code == 401
    assert res.json() == {"detail": "Invalid or expired OTP."}


def test_submit_otp_failure_returns_502(client, monkeypatch):
    cls = make_fake_authenticator_cls(otp_required=True, otp_raises=True)
    _register(monkeypatch, "zerodha", cls)

    client.post("/auth/zerodha/start", json={"user_id": "u1", "password": "p1"})
    res = client.post("/auth/zerodha/otp", json={"otp": "000000"})

    assert res.status_code == 502


def test_submit_otp_without_pending_session_is_404(client, monkeypatch):
    cls = make_fake_authenticator_cls(otp_required=True)
    _register(monkeypatch, "zerodha", cls)

    res = client.post("/auth/zerodha/otp", json={"otp": "000000"})

    assert res.status_code == 404


def test_second_start_while_pending_conflicts_and_tears_down_the_redundant_one(client, monkeypatch):
    cls = make_fake_authenticator_cls(otp_required=True)
    _register(monkeypatch, "zerodha", cls)

    client.post("/auth/zerodha/start", json={"user_id": "u1", "password": "p1"})
    res = client.post("/auth/zerodha/start", json={"user_id": "u2", "password": "p2"})

    assert res.status_code == 409
    assert cls.instances[1].aborted is True


def test_cancel_pending_session(client, monkeypatch):
    cls = make_fake_authenticator_cls(otp_required=True)
    _register(monkeypatch, "zerodha", cls)

    client.post("/auth/zerodha/start", json={"user_id": "u1", "password": "p1"})
    res = client.post("/auth/zerodha/cancel")

    assert res.status_code == 200
    assert res.json() == {"status": "cancelled"}
    assert cls.instances[0].aborted is True

    res2 = client.post("/auth/zerodha/otp", json={"otp": "000000"})
    assert res2.status_code == 404


def test_cancel_without_pending_session_is_404(client):
    res = client.post("/auth/zerodha/cancel")
    assert res.status_code == 404


def test_credentials_and_token_never_appear_in_logs(client, monkeypatch, caplog):
    cls = make_fake_authenticator_cls(otp_required=True)
    _register(monkeypatch, "zerodha", cls)
    caplog.set_level("DEBUG")

    client.post("/auth/zerodha/start", json={"user_id": "u1", "password": "SuperSecretPW"})
    client.post("/auth/zerodha/otp", json={"otp": "999111"})

    log_text = caplog.text
    assert "SuperSecretPW" not in log_text
    assert "999111" not in log_text
    assert "SECRET-TOKEN-SHOULD-NOT-LEAK" not in log_text


def test_failure_logs_do_not_leak_credentials(client, monkeypatch, caplog):
    cls = make_fake_authenticator_cls(start_raises=True)
    _register(monkeypatch, "zerodha", cls)
    caplog.set_level("DEBUG")

    client.post("/auth/zerodha/start", json={"user_id": "u1", "password": "AnotherSecret"})

    assert "AnotherSecret" not in caplog.text


def test_access_token_never_appears_in_any_response(client, monkeypatch):
    cls = make_fake_authenticator_cls(otp_required=True)
    _register(monkeypatch, "zerodha", cls)

    r1 = client.post("/auth/zerodha/start", json={"user_id": "u1", "password": "p1"})
    r2 = client.post("/auth/zerodha/otp", json={"otp": "123456"})

    for res in (r1, r2):
        assert "access_token" not in res.json()
        assert "SECRET-TOKEN-SHOULD-NOT-LEAK" not in res.text


def test_list_brokers(client):
    res = client.get("/brokers")
    assert res.status_code == 200
    brokers = res.json()["brokers"]
    assert "zerodha" in brokers
    assert "mastertrust" in brokers
