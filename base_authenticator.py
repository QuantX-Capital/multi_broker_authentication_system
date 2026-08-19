from abc import ABC, abstractmethod


class BrokerAuthenticator(ABC):
    """Common interface every broker authenticator must implement."""

    access_token = None

    @abstractmethod
    def authenticate(self):
        """Run the broker's login flow and return the access token."""
        raise NotImplementedError
