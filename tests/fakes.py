"""Test doubles shared across the test suite. None of these touch a real
browser, AWS, or the network."""

import json


class FakeSecretsClient:
    """Stands in for the boto3 Secrets Manager client."""

    def __init__(self, secret):
        self._secret = dict(secret)
        self.put_calls = []

    def get_secret_value(self, SecretId):
        return {"SecretString": json.dumps(self._secret)}

    def put_secret_value(self, SecretId, SecretString):
        self._secret = json.loads(SecretString)
        self.put_calls.append(dict(self._secret))


class _RecordingElement:
    """Stands in for a Selenium WebElement. click() and send_keys() invoke
    whatever callbacks the owning fake driver gave them - each fake driver
    wires these up to model the specific page-transition behavior it's
    simulating (a button click, or a broker page that auto-submits once a
    value is typed)."""

    def __init__(self, driver, on_click=None, on_send_keys=None, text=""):
        self._driver = driver
        self._on_click_cb = on_click
        self._on_send_keys_cb = on_send_keys
        self.sent_keys = []
        self.text = text

    def send_keys(self, value):
        self.sent_keys.append(value)
        if self._on_send_keys_cb:
            self._on_send_keys_cb(value)

    def click(self):
        if self._on_click_cb:
            self._on_click_cb()

    def is_displayed(self):
        return True


class ScriptedDriver:
    """Stands in for a Selenium Chrome driver.

    Simulates a broker login page: clicking the credentials-submit button
    either reveals an OTP input or redirects straight to the callback URL.
    Once revealed, entering a value into the OTP input (send_keys) itself
    triggers the redirect - mirroring Zerodha's page, which submits itself
    automatically once the OTP is typed and has no button to click. No real
    navigation happens - by/value locators are accepted but ignored, since
    orchestration logic (not exact CSS/XPath selectors) is what these tests
    exercise.
    """

    def __init__(self, redirect_query_param, redirect_value, otp_required=True):
        self.current_url = "https://broker.example/login"
        self.quit_called = False
        self._redirect_query_param = redirect_query_param
        self._redirect_value = redirect_value
        self._otp_required = otp_required
        self._otp_visible = False

    def get(self, url):
        self.current_url = url

    def find_element(self, by, value):
        return _RecordingElement(self, on_click=self._handle_credentials_submit)

    def find_elements(self, by, value):
        if self._otp_visible:
            return [_RecordingElement(self, on_send_keys=self._handle_otp_entered)]
        return []

    def _handle_credentials_submit(self):
        if self._otp_required:
            self._otp_visible = True
        else:
            self._redirect()

    def _handle_otp_entered(self, value):
        self._redirect()

    def _redirect(self):
        self.current_url = (
            f"https://broker.example/callback"
            f"?{self._redirect_query_param}={self._redirect_value}"
        )
        self._otp_visible = False

    def quit(self):
        self.quit_called = True


class NoSubmitButtonDriver:
    """Regression guard for Zerodha's OTP auto-submit fix: find_element()
    must never be called from submit_otp() - production hit
    NoSuchElementException there because the old code looked up and clicked
    a submit button that doesn't exist on Zerodha's OTP page. Entering the
    OTP (send_keys) triggers the redirect on its own, exactly like the real
    page does."""

    def __init__(self, redirect_query_param, redirect_value):
        self.current_url = "https://broker.example/login"
        self.quit_called = False
        self._redirect_query_param = redirect_query_param
        self._redirect_value = redirect_value

    def get(self, url):
        self.current_url = url

    def find_element(self, by, value):
        raise AssertionError(
            f"find_element({value!r}) must not be called here - "
            "Zerodha's OTP page has no submit button to locate/click."
        )

    def find_elements(self, by, value):
        return [_RecordingElement(self, on_send_keys=self._handle_otp_entered)]

    def _handle_otp_entered(self, value):
        self.current_url = (
            f"https://broker.example/callback"
            f"?{self._redirect_query_param}={self._redirect_value}"
        )

    def quit(self):
        self.quit_called = True


class SinglePageOtpDriver:
    """Stands in for a Selenium Chrome driver modeling MasterTrust-style
    login pages: user ID, password, and OTP inputs all live on one page from
    the start. A distinct "Get OTP" click (class "getotp") requests the OTP;
    a separate final "LOGIN" click (class "lgnBtnClss", via find_element)
    submits everything and redirects. No real navigation happens - by/value
    locators are otherwise ignored, since orchestration logic is what these
    tests exercise.

    If `credentials_error_text` is set, a fake error-toast element (matching
    MasterTrustAuthenticator.ERROR_TOAST_CSS) becomes findable right after
    the "Get OTP" click - simulating MasterTrust's Vue-mounted "Invalid
    User" toast for wrong credentials. If `otp_error_text` is set instead,
    that same fake toast becomes findable after the LOGIN click (instead of
    redirecting) - simulating a wrong/expired OTP.
    """

    ERROR_TOAST_CSS = ".toastContent.error-toast .toast-text"

    def __init__(
        self, redirect_query_param, redirect_value, credentials_error_text=None, otp_error_text=None
    ):
        self.current_url = "https://broker.example/login"
        self.quit_called = False
        self.get_otp_clicked = False
        self._redirect_query_param = redirect_query_param
        self._redirect_value = redirect_value
        self._credentials_error_text = credentials_error_text
        self._otp_error_text = otp_error_text
        self._show_credentials_error = False

    def get(self, url):
        self.current_url = url

    def find_element(self, by, value):
        # Only the final LOGIN button is ever find_element'd and clicked;
        # user_id/password lookups only ever get send_keys().
        return _RecordingElement(self, on_click=self._handle_login_click)

    def find_elements(self, by, value):
        if value == self.ERROR_TOAST_CSS:
            # MasterTrustAuthenticator's toast lookups (both Get-OTP-stage
            # and post-LOGIN-click stage use this same selector).
            if self._show_credentials_error:
                text = self._credentials_error_text or self._otp_error_text
                return [_RecordingElement(self, text=text)]
            return []
        if value == "getotp":
            return [_RecordingElement(self, on_click=self._handle_get_otp_click)]
        if value == "lgnotp":
            # The OTP field is present in the DOM from page load.
            return [_RecordingElement(self)]
        return []

    def _handle_get_otp_click(self):
        self.get_otp_clicked = True
        if self._credentials_error_text:
            self._show_credentials_error = True

    def _handle_login_click(self):
        if self._otp_error_text:
            self._show_credentials_error = True
            return
        self.current_url = (
            f"https://broker.example/callback"
            f"?{self._redirect_query_param}={self._redirect_value}"
        )

    def quit(self):
        self.quit_called = True


def make_fake_authenticator_cls(
    otp_required=True,
    start_raises=False,
    start_raises_invalid_credentials=False,
    otp_raises=False,
    otp_raises_invalid_credentials=False,
):
    """Builds a fake BrokerAuthenticator-shaped class for testing main.py's
    orchestration in isolation from any real broker/Selenium logic. Created
    instances are collected on the class's `instances` list."""

    from base_authenticator import InvalidCredentials

    instances = []

    class FakeAuthenticator:
        def __init__(self):
            self.aborted = False
            self.seen_password = None
            self.seen_otp = None
            self.access_token = None
            instances.append(self)

        def start_login(self, user_id, password, on_status=None):
            self.seen_password = password
            if start_raises_invalid_credentials:
                raise InvalidCredentials("simulated invalid credentials")
            if start_raises:
                raise RuntimeError("simulated start_login failure")
            return otp_required

        def submit_otp(self, otp, on_status=None):
            self.seen_otp = otp
            if otp_raises_invalid_credentials:
                raise InvalidCredentials("simulated invalid OTP")
            if otp_raises:
                raise RuntimeError("simulated submit_otp failure")
            self.access_token = "SECRET-TOKEN-SHOULD-NOT-LEAK"
            return self.access_token

        def abort(self):
            self.aborted = True

    FakeAuthenticator.instances = instances
    return FakeAuthenticator
