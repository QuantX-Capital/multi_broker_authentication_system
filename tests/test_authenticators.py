"""Tests the real Zerodha/MasterTrust authenticator classes with a fake
Selenium driver, fake Secrets Manager client, and fake HTTP token exchange -
no real browser, AWS, or network calls."""

import boto3
import pytest
import requests

from selenium.webdriver.common.by import By

from fakes import FakeSecretsClient, NoSubmitButtonDriver, ScriptedDriver, SinglePageOtpDriver

from base_authenticator import AuthCancelled, InvalidCredentials

ZERODHA_SECRET = {"api_key": "K1", "secret_key": "S1", "user_id": "ZUSER"}
MASTERTRUST_SECRET = {"client_id": "C1", "secret_key": "S2", "user_id": "MUSER"}


def _patch_boto3(monkeypatch, secret):
    client = FakeSecretsClient(secret)
    monkeypatch.setattr(boto3, "client", lambda *a, **k: client)
    return client


def _patch_chrome(monkeypatch, driver):
    import selenium.webdriver as sw

    monkeypatch.setattr(sw, "Chrome", lambda options=None: driver)


def _patch_requests_post(monkeypatch, json_data, status_code=200):
    class FakeResponse:
        def __init__(self):
            self.status_code = status_code

        def json(self):
            return json_data

    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResponse())


@pytest.fixture(autouse=True)
def _fast_get_otp_error_check(monkeypatch):
    """start_login() polls for MasterTrust's 'Get OTP' error toast for up to
    GET_OTP_ERROR_CHECK_TIMEOUT seconds on every call, including the happy
    path. Shrink that window so the test suite doesn't pay real wall-clock
    time for it."""
    from mastertrust import MasterTrustAuthenticator

    monkeypatch.setattr(MasterTrustAuthenticator, "GET_OTP_ERROR_CHECK_TIMEOUT", 0.05)


class TestZerodhaAuthenticator:
    def test_start_login_reports_otp_required(self, monkeypatch):
        _patch_boto3(monkeypatch, ZERODHA_SECRET)
        driver = ScriptedDriver("request_token", "RTOK", otp_required=True)
        _patch_chrome(monkeypatch, driver)

        from zerodha import ZerodhaAuthenticator

        auth = ZerodhaAuthenticator()

        assert auth.start_login("uid", "pwd") is True
        assert driver.quit_called is False  # kept open for submit_otp
        assert auth.access_token is None

    def test_submit_otp_completes_authentication(self, monkeypatch):
        client = _patch_boto3(monkeypatch, ZERODHA_SECRET)
        driver = ScriptedDriver("request_token", "RTOK", otp_required=True)
        _patch_chrome(monkeypatch, driver)
        _patch_requests_post(monkeypatch, {"data": {"access_token": "ACCESS1"}})

        from zerodha import ZerodhaAuthenticator

        auth = ZerodhaAuthenticator()
        assert auth.start_login("uid", "pwd") is True

        token = auth.submit_otp("999999")

        assert token == "ACCESS1"
        assert auth.access_token == "ACCESS1"
        assert driver.quit_called is True
        assert client.put_calls[-1]["access_token"] == "ACCESS1"

    def test_start_login_without_otp_completes_immediately(self, monkeypatch):
        _patch_boto3(monkeypatch, ZERODHA_SECRET)
        driver = ScriptedDriver("request_token", "RTOK", otp_required=False)
        _patch_chrome(monkeypatch, driver)
        _patch_requests_post(monkeypatch, {"data": {"access_token": "ACCESS2"}})

        from zerodha import ZerodhaAuthenticator

        auth = ZerodhaAuthenticator()

        assert auth.start_login("uid", "pwd") is False
        assert auth.access_token == "ACCESS2"
        assert driver.quit_called is True  # no submit_otp call coming - must not leak the process

    def test_cancel_aborts_the_browser_session(self, monkeypatch):
        _patch_boto3(monkeypatch, ZERODHA_SECRET)
        driver = ScriptedDriver("request_token", "RTOK", otp_required=True)
        _patch_chrome(monkeypatch, driver)

        from zerodha import ZerodhaAuthenticator

        auth = ZerodhaAuthenticator()
        auth.cancel()

        with pytest.raises(AuthCancelled):
            auth.start_login("uid", "pwd")
        assert driver.quit_called is True

    def test_submit_otp_never_looks_up_a_submit_button(self, monkeypatch):
        """Regression test for the production NoSuchElementException on
        //button[@type="submit"]: Zerodha's OTP page submits itself once the
        OTP is typed, so submit_otp() must not call find_element() at all."""
        client = _patch_boto3(monkeypatch, ZERODHA_SECRET)
        _patch_requests_post(monkeypatch, {"data": {"access_token": "ACCESS5"}})

        from zerodha import ZerodhaAuthenticator

        auth = ZerodhaAuthenticator()
        driver = NoSubmitButtonDriver("request_token", "RTOK")
        auth._driver = driver
        auth._By = By

        token = auth.submit_otp("654321")

        assert token == "ACCESS5"
        assert auth.access_token == "ACCESS5"
        assert driver.quit_called is True
        assert client.put_calls[-1]["access_token"] == "ACCESS5"


class TestMasterTrustAuthenticator:
    """MasterTrust's login page keeps user ID, password, and OTP/TOTP all on
    one page. start_login fills credentials and clicks the distinct "Get
    OTP" link; it never sees the redirect itself, so - unlike Zerodha - it
    always returns True. submit_otp fills the OTP and clicks the single
    LOGIN button that submits everything and redirects."""

    def test_start_login_clicks_get_otp_and_returns_true(self, monkeypatch):
        _patch_boto3(monkeypatch, MASTERTRUST_SECRET)
        driver = SinglePageOtpDriver("code", "AUTHCODE")
        _patch_chrome(monkeypatch, driver)

        from mastertrust import MasterTrustAuthenticator

        auth = MasterTrustAuthenticator()

        assert auth.start_login("uid", "pwd") is True
        assert driver.get_otp_clicked is True
        assert driver.quit_called is False  # kept open for submit_otp
        assert auth.access_token is None

    def test_submit_otp_completes_authentication(self, monkeypatch):
        client = _patch_boto3(monkeypatch, MASTERTRUST_SECRET)
        driver = SinglePageOtpDriver("code", "AUTHCODE")
        _patch_chrome(monkeypatch, driver)
        _patch_requests_post(monkeypatch, {"stat": "Ok", "access_token": "ACCESS3"})

        from mastertrust import MasterTrustAuthenticator

        auth = MasterTrustAuthenticator()
        assert auth.start_login("uid", "pwd") is True

        token = auth.submit_otp("111111")

        assert token == "ACCESS3"
        assert auth.access_token == "ACCESS3"
        assert driver.quit_called is True
        assert client.put_calls[-1]["access_token"] == "ACCESS3"

    def test_cancel_aborts_the_browser_session(self, monkeypatch):
        _patch_boto3(monkeypatch, MASTERTRUST_SECRET)
        driver = SinglePageOtpDriver("code", "AUTHCODE")
        _patch_chrome(monkeypatch, driver)

        from mastertrust import MasterTrustAuthenticator

        auth = MasterTrustAuthenticator()
        auth.cancel()

        with pytest.raises(AuthCancelled):
            auth.start_login("uid", "pwd")
        assert driver.quit_called is True

    def test_missing_client_id_raises(self, monkeypatch):
        _patch_boto3(monkeypatch, {"secret_key": "S2"})  # no client_id

        from mastertrust import MasterTrustAuthenticator

        with pytest.raises(ValueError):
            MasterTrustAuthenticator()

    def test_start_login_raises_on_invalid_credentials_toast(self, monkeypatch):
        """Regression test: clicking 'Get OTP' with a wrong user ID/password
        surfaces an 'Invalid User' toast instead of sending an OTP.
        start_login() must not report otp_required in that case."""
        _patch_boto3(monkeypatch, MASTERTRUST_SECRET)
        driver = SinglePageOtpDriver("code", "AUTHCODE", credentials_error_text="Invalid User")
        _patch_chrome(monkeypatch, driver)

        from mastertrust import MasterTrustAuthenticator

        auth = MasterTrustAuthenticator()

        with pytest.raises(InvalidCredentials, match="Invalid User"):
            auth.start_login("uid", "wrong-password")

        assert driver.get_otp_clicked is True
        assert driver.quit_called is True  # torn down, not left dangling

    def test_submit_otp_raises_quickly_on_rejected_otp_toast(self, monkeypatch):
        """Regression test: a wrong/expired OTP surfaces the same error
        toast after the LOGIN click instead of redirecting. submit_otp()
        must detect it and fail fast, not hang for the full REDIRECT_TIMEOUT
        (previously 600s) waiting for a redirect that will never come."""
        _patch_boto3(monkeypatch, MASTERTRUST_SECRET)
        driver = SinglePageOtpDriver("code", "AUTHCODE", otp_error_text="Invalid OTP")
        _patch_chrome(monkeypatch, driver)

        from mastertrust import MasterTrustAuthenticator

        auth = MasterTrustAuthenticator()
        assert auth.start_login("uid", "pwd") is True

        with pytest.raises(InvalidCredentials, match="Invalid OTP"):
            auth.submit_otp("000000")

        assert driver.quit_called is True
