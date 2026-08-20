from abc import ABC, abstractmethod


class AuthCancelled(Exception):
    """Raised inside a login flow when a session is cancelled from outside."""


class BrokerAuthenticator(ABC):
    """Common interface every broker authenticator must implement."""

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
    def authenticate(self, on_status=None):
        """Run the broker's login flow and return the access token.

        on_status, if given, is called with a short status string
        (e.g. "starting_browser", "waiting_for_otp", "authenticating")
        at the same milestones the login flow already passes through.
        """
        raise NotImplementedError
