import datetime
import time

import pytest

import session_manager


class FakeAuthenticator:
    def __init__(self):
        self.aborted = False

    def abort(self):
        self.aborted = True


@pytest.fixture(autouse=True)
def reset_pending_sessions():
    session_manager._pending.clear()
    yield
    session_manager._pending.clear()


def test_start_then_pop_returns_the_session():
    auth = FakeAuthenticator()
    session = session_manager.start_session("zerodha", auth)

    popped = session_manager.pop_session("zerodha")

    assert popped is session
    assert popped.authenticator is auth


def test_pop_consumes_the_session():
    session_manager.start_session("zerodha", FakeAuthenticator())

    session_manager.pop_session("zerodha")

    assert session_manager.pop_session("zerodha") is None


def test_pop_unknown_broker_returns_none():
    assert session_manager.pop_session("nobroker") is None


def test_second_start_for_same_broker_raises():
    session_manager.start_session("zerodha", FakeAuthenticator())

    with pytest.raises(session_manager.SessionInProgress):
        session_manager.start_session("zerodha", FakeAuthenticator())


def test_different_brokers_can_be_pending_simultaneously():
    session_manager.start_session("zerodha", FakeAuthenticator())
    session_manager.start_session("mastertrust", FakeAuthenticator())  # must not raise

    assert session_manager.pop_session("zerodha") is not None
    assert session_manager.pop_session("mastertrust") is not None


def test_cancel_session_aborts_authenticator_and_removes_it():
    auth = FakeAuthenticator()
    session_manager.start_session("zerodha", auth)

    cancelled = session_manager.cancel_session("zerodha")

    assert cancelled is not None
    assert auth.aborted is True
    assert session_manager.pop_session("zerodha") is None


def test_cancel_unknown_broker_returns_none():
    assert session_manager.cancel_session("nobroker") is None


def test_abandoned_session_expires_and_aborts(monkeypatch):
    monkeypatch.setattr(session_manager, "OTP_WAIT_TIMEOUT", datetime.timedelta(seconds=0.05))
    auth = FakeAuthenticator()
    session_manager.start_session("zerodha", auth)

    time.sleep(0.3)

    assert auth.aborted is True
    assert session_manager.pop_session("zerodha") is None


def test_starting_a_new_session_after_expiry_succeeds(monkeypatch):
    monkeypatch.setattr(session_manager, "OTP_WAIT_TIMEOUT", datetime.timedelta(seconds=0.05))
    session_manager.start_session("zerodha", FakeAuthenticator())

    time.sleep(0.3)

    second = FakeAuthenticator()
    session_manager.start_session("zerodha", second)  # must not raise SessionInProgress

    assert session_manager.pop_session("zerodha").authenticator is second
