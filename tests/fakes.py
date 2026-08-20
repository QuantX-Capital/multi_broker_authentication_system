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
    """Stands in for a Selenium WebElement. send_keys() just records what it
    was given; click() invokes whatever callback the owning fake driver gave
    it (defaulting to the driver's own _on_click, for drivers that track
    clicks by count rather than by which element was clicked)."""

    def __init__(self, driver, on_click=None):
        self._driver = driver
        self._on_click_cb = on_click or driver._on_click
        self.sent_keys = []

    def send_keys(self, value):
        self.sent_keys.append(value)

    def click(self):
        self._on_click_cb()

    def is_displayed(self):
        return True


class ScriptedDriver:
    """Stands in for a Selenium Chrome driver.

    Simulates a broker login page: the first click (submitting the
    credentials form) either reveals an OTP input or redirects straight to
    the callback URL; the second click (submitting the OTP) always
    redirects to the callback URL. No real navigation happens - by/value
    locators are accepted but ignored, since orchestration logic (not exact
    CSS/XPath selectors) is what these tests exercise.
    """

    def __init__(self, redirect_query_param, redirect_value, otp_required=True):
        self.current_url = "https://broker.example/login"
        self.quit_called = False
        self._redirect_query_param = redirect_query_param
        self._redirect_value = redirect_value
        self._otp_required = otp_required
        self._otp_visible = False
        self._click_count = 0

    def get(self, url):
        self.current_url = url

    def find_element(self, by, value):
        return _RecordingElement(self)

    def find_elements(self, by, value):
        return [_RecordingElement(self)] if self._otp_visible else []

    def _on_click(self):
        self._click_count += 1
        if self._click_count == 1 and self._otp_required:
            self._otp_visible = True
        else:
            self._redirect()

    def _redirect(self):
        self.current_url = (
            f"https://broker.example/callback"
            f"?{self._redirect_query_param}={self._redirect_value}"
        )
        self._otp_visible = False

    def quit(self):
        self.quit_called = True


class SinglePageOtpDriver:
    """Stands in for a Selenium Chrome driver modeling MasterTrust-style
    login pages: user ID, password, and OTP inputs all live on one page from
    the start. A distinct "Get OTP" click (looked up by visible text, via
    find_clickable_by_text) requests the OTP; a separate final "LOGIN" click
    (looked up by id/class, via find_element) submits everything and
    redirects. No real navigation happens - by/value locators are otherwise
    ignored, since orchestration logic is what these tests exercise.
    """

    def __init__(self, redirect_query_param, redirect_value):
        self.current_url = "https://broker.example/login"
        self.quit_called = False
        self.get_otp_clicked = False
        self._redirect_query_param = redirect_query_param
        self._redirect_value = redirect_value

    def get(self, url):
        self.current_url = url

    def find_element(self, by, value):
        # Only the final LOGIN button is ever find_element'd and clicked;
        # user_id/password lookups only ever get send_keys().
        return _RecordingElement(self, on_click=self._handle_login_click)

    def find_elements(self, by, value):
        if "normalize-space(.)" in value:
            # find_clickable_by_text's "Get OTP" lookup.
            return [_RecordingElement(self, on_click=self._handle_get_otp_click)]
        # find_otp_input's lookup - the OTP field is present from page load.
        return [_RecordingElement(self)]

    def _on_click(self):
        # Only reached if something clicks an element that wasn't given an
        # explicit on_click handler (e.g. the OTP input) - that would be a
        # bug in the code under test, not expected fake-driver behavior.
        raise AssertionError("unexpected click on an element with no handler")

    def _handle_get_otp_click(self):
        self.get_otp_clicked = True

    def _handle_login_click(self):
        self.current_url = (
            f"https://broker.example/callback"
            f"?{self._redirect_query_param}={self._redirect_value}"
        )

    def quit(self):
        self.quit_called = True


def make_fake_authenticator_cls(otp_required=True, start_raises=False, otp_raises=False):
    """Builds a fake BrokerAuthenticator-shaped class for testing main.py's
    orchestration in isolation from any real broker/Selenium logic. Created
    instances are collected on the class's `instances` list."""

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
            if start_raises:
                raise RuntimeError("simulated start_login failure")
            return otp_required

        def submit_otp(self, otp, on_status=None):
            self.seen_otp = otp
            if otp_raises:
                raise RuntimeError("simulated submit_otp failure")
            self.access_token = "SECRET-TOKEN-SHOULD-NOT-LEAK"
            return self.access_token

        def abort(self):
            self.aborted = True

    FakeAuthenticator.instances = instances
    return FakeAuthenticator
