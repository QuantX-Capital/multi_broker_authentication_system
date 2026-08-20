import json
import hashlib
import time
from urllib.parse import urlparse, parse_qs

import boto3
import requests
from base_authenticator import BrokerAuthenticator


class ZerodhaAuthenticator(BrokerAuthenticator):
    """Handles Zerodha Kite Connect login, backed by an AWS Secrets Manager secret."""

    LOGIN_URL = "https://kite.zerodha.com/connect/login?v=3&api_key={api_key}"
    TOKEN_URL = "https://api.kite.trade/session/token"
    PROFILE_URL = "https://api.kite.trade/user/profile"

    def __init__(self, secret_id="/trading/brokers/zerodha/luv", region_name="ap-south-1"):
        super().__init__()
        self.secret_id = secret_id
        self.client = boto3.client("secretsmanager", region_name=region_name)

        secret = self._get_secret()
        self.api_key = secret["api_key"]
        self.api_secret = secret["secret_key"]
        self.redirect_url = secret.get("redirect_url")
        self.access_token = secret.get("access_token") or None
        self.user_id = secret.get("user_id")
        self.password = secret.get("password")

    def _get_secret(self):
        response = self.client.get_secret_value(SecretId=self.secret_id)
        return json.loads(response["SecretString"])

    def _update_secret(self, access_token):
        secret = self._get_secret()
        secret["access_token"] = access_token
        self.client.put_secret_value(
            SecretId=self.secret_id,
            SecretString=json.dumps(secret),
        )

    def get_login_url(self):
        return self.LOGIN_URL.format(api_key=self.api_key)

    def exchange_request_token(self, request_token):
        """Exchange a Kite request_token for an access_token and persist it to the secret."""
        checksum = hashlib.sha256(
            (self.api_key + request_token + self.api_secret).encode("utf-8")
        ).hexdigest()

        response = requests.post(
            self.TOKEN_URL,
            data={
                "api_key": self.api_key,
                "request_token": request_token,
                "checksum": checksum,
            },
        )

        data = response.json()
        if response.status_code != 200:
            raise RuntimeError(f"Token exchange failed: {data}")

        access_token = data["data"]["access_token"]
        self.access_token = access_token
        self._update_secret(access_token)
        return access_token

    def login_via_browser(self, timeout=600, poll_interval=1, on_status=None):
        """Opens a Selenium-driven browser, auto-fills the user ID/password if
        available, and waits for you to complete the OTP step. Once Zerodha
        redirects back with request_token in the URL, it's captured automatically
        and exchanged for an access token."""
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC

        on_status = on_status or (lambda status: None)

        driver = webdriver.Chrome()
        try:
            on_status("starting_browser")
            driver.get(self.get_login_url())

            if self.user_id and self.password:
                WebDriverWait(driver, 20).until(
                    EC.presence_of_element_located((By.ID, "userid"))
                )
                driver.find_element(By.ID, "userid").send_keys(self.user_id)
                driver.find_element(By.ID, "password").send_keys(self.password)
                driver.find_element(By.XPATH, '//button[@type="submit"]').click()

            on_status("waiting_for_otp")
            request_token = None
            elapsed = 0
            while elapsed < timeout:
                self._raise_if_cancelled()
                query = parse_qs(urlparse(driver.current_url).query)
                if "request_token" in query:
                    request_token = query["request_token"][0]
                    break
                time.sleep(poll_interval)
                elapsed += poll_interval

            if not request_token:
                raise TimeoutError("Timed out waiting for the login redirect containing request_token.")

            on_status("authenticating")
        finally:
            driver.quit()

        return self.exchange_request_token(request_token)

    def get_headers(self):
        if not self.access_token:
            raise RuntimeError("No access token available. Call authenticate() first.")
        return {
            "X-Kite-Version": "3",
            "Authorization": f"token {self.api_key}:{self.access_token}",
        }

    def authenticate(self, on_status=None):
        """Always runs the full browser login flow."""
        return self.login_via_browser(on_status=on_status)

    def get_profile(self):
        response = requests.get(self.PROFILE_URL, headers=self.get_headers())
        return response.json()


if __name__ == "__main__":
    auth = ZerodhaAuthenticator()
    auth.authenticate()
    print("Access token:", auth.access_token)
    print(auth.get_profile())
