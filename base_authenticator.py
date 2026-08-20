from abc import ABC, abstractmethod


class AuthCancelled(Exception):
    """Raised inside a login flow when a session is cancelled from outside."""


class InvalidCredentials(Exception):
    """Raised when the broker itself rejects the user ID/password outright
    (e.g. an "Invalid User" toast), as opposed to any other login failure
    (selector not found, timeout, network error, etc). Callers can catch
    this specifically to show a clear "wrong credentials" message instead of
    a generic failure."""


# Best-effort OTP input locator shared by broker authenticators. The original
# code never automated OTP entry (a human typed it into the VNC-embedded
# browser), so there is no pre-existing selector to preserve here - this
# heuristic should be verified against each broker's live login page and
# tightened with a broker-specific selector if it proves unreliable.
OTP_INPUT_XPATH = (
    '//input[@type="number" or @type="tel" or '
    'contains(translate(@id, "OTP", "otp"), "otp") or '
    'contains(translate(@name, "OTP", "otp"), "otp")]'
)


def find_otp_input(driver, by):
    """Returns the first visible element on the page that looks like an OTP
    input, or None if none is present yet."""
    for element in driver.find_elements(by.XPATH, OTP_INPUT_XPATH):
        if element.is_displayed():
            return element
    return None


class BrokerAuthenticator(ABC):
    """Common interface every broker authenticator must implement.

    The login flow is split into two steps so credentials and the OTP can be
    supplied programmatically, one at a time, over the API:

        start_login(user_id, password) -> True if the broker is now waiting
                                            for an OTP, False if login already
                                            completed without one.
        submit_otp(otp)                -> completes the login and returns the
                                            access token.

    A single authenticator instance is stateful across this pair of calls: it
    keeps the Selenium driver open between start_login() and submit_otp().
    """

    access_token = None

    def __init__(self):
        self._cancelled = False

    def cancel(self):
        """Ask a running login flow to stop at its next poll tick."""
        self._cancelled = True

    def _raise_if_cancelled(self):
        if self._cancelled:
            raise AuthCancelled("Authentication session was cancelled.")

    @abstractmethod
    def start_login(self, user_id, password, on_status=None):
        """Launch Selenium (headless) and submit credentials to the broker.

        on_status, if given, is called with a short status string (e.g.
        "starting_browser", "waiting_for_otp", "authenticating") at the same
        milestones the login flow passes through.

        Returns True if the broker is now showing an OTP prompt and
        submit_otp() must be called next, or False if authentication already
        completed (access_token is set).
        """
        raise NotImplementedError

    @abstractmethod
    def submit_otp(self, otp, on_status=None):
        """Enter the OTP into the page opened by start_login() and complete
        authentication. Returns the access token."""
        raise NotImplementedError

    @abstractmethod
    def abort(self):
        """Tear down any in-progress Selenium session without completing
        authentication (used on cancellation, failure, or session expiry)."""
        raise NotImplementedError
