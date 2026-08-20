import json
import hashlib
import time
from urllib.parse import urlparse, parse_qs

import boto3
import requests
from base_authenticator import BrokerAuthenticator, find_otp_input


class ZerodhaAuthenticator(BrokerAuthenticator):
    """Handles Zerodha Kite Connect login, backed by an AWS Secrets Manager secret."""

    LOGIN_URL = "https://kite.zerodha.com/connect/login?v=3&api_key={api_key}"
    TOKEN_URL = "https://api.kite.trade/session/token"
    PROFILE_URL = "https://api.kite.trade/user/profile"

    CREDENTIALS_TIMEOUT = 20
    OTP_PROMPT_TIMEOUT = 20
    REDIRECT_TIMEOUT = 600

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

        self._driver = None

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

    def start_login(self, user_id, password, on_status=None):
        """Opens a headless Selenium-driven Chrome, fills in the user ID and
        password, and submits the login form. Returns True if Zerodha is now
        showing an OTP/TOTP prompt (submit_otp() must be called next), or
        False if the redirect with request_token already arrived without one."""
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC

        on_status = on_status or (lambda status: None)

        options = webdriver.ChromeOptions()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")

        driver = webdriver.Chrome(options=options)
        self._driver = driver
        self._By = By

        try:
            on_status("starting_browser")
            driver.get(self.get_login_url())

            WebDriverWait(driver, self.CREDENTIALS_TIMEOUT).until(
                EC.presence_of_element_located((By.ID, "userid"))
            )
            driver.find_element(By.ID, "userid").send_keys(user_id)
            driver.find_element(By.ID, "password").send_keys(password)
            driver.find_element(By.XPATH, '//button[@type="submit"]').click()

            on_status("waiting_for_otp")
            elapsed = 0.0
            poll_interval = 0.5
            while elapsed < self.OTP_PROMPT_TIMEOUT:
                self._raise_if_cancelled()
                if "request_token" in parse_qs(urlparse(driver.current_url).query):
                    on_status("authenticating")
                    self._finish_from_redirect(driver)
                    self.abort()
                    return False
                if find_otp_input(driver, By) is not None:
                    return True
                time.sleep(poll_interval)
                elapsed += poll_interval

            raise TimeoutError("Timed out waiting for the OTP prompt or login redirect.")
        except Exception:
            self.abort()
            raise

    def submit_otp(self, otp, on_status=None):
        """Enters the OTP/TOTP into the already-open login page and waits for
        the redirect containing request_token, then exchanges it for an
        access token."""
        if self._driver is None:
            raise RuntimeError("start_login() must be called before submit_otp().")

        on_status = on_status or (lambda status: None)
        driver = self._driver
        By = self._By

        try:
            otp_field = find_otp_input(driver, By)
            if otp_field is None:
                raise RuntimeError("OTP input field is no longer present on the page.")
            otp_field.send_keys(otp)
            driver.find_element(By.XPATH, '//button[@type="submit"]').click()

            on_status("authenticating")
            return self._finish_from_redirect(driver)
        finally:
            self.abort()

    def _finish_from_redirect(self, driver):
        request_token = None
        elapsed = 0
        poll_interval = 1
        while elapsed < self.REDIRECT_TIMEOUT:
            self._raise_if_cancelled()
            query = parse_qs(urlparse(driver.current_url).query)
            if "request_token" in query:
                request_token = query["request_token"][0]
                break
            time.sleep(poll_interval)
            elapsed += poll_interval

        if not request_token:
            raise TimeoutError("Timed out waiting for the login redirect containing request_token.")

        return self.exchange_request_token(request_token)

    def abort(self):
        if self._driver is not None:
            try:
                self._driver.quit()
            finally:
                self._driver = None

    def get_headers(self):
        if not self.access_token:
            raise RuntimeError("No access token available. Call authenticate() first.")
        return {
            "X-Kite-Version": "3",
            "Authorization": f"token {self.api_key}:{self.access_token}",
        }

    def authenticate(self, on_status=None):
        """Convenience wrapper for local/console use (see __main__ below):
        runs the full login flow using the secret's stored user_id, prompting
        for the password and OTP on the console instead of over the API."""
        import getpass

        password = getpass.getpass(f"Zerodha password for {self.user_id}: ")
        try:
            otp_required = self.start_login(self.user_id, password, on_status=on_status)
        finally:
            password = None

        if not otp_required:
            return self.access_token

        otp = input("Zerodha OTP/TOTP: ")
        try:
            return self.submit_otp(otp, on_status=on_status)
        finally:
            otp = None

    def get_profile(self):
        response = requests.get(self.PROFILE_URL, headers=self.get_headers())
        return response.json()


if __name__ == "__main__":
    auth = ZerodhaAuthenticator()
    auth.authenticate()
    print("Authenticated. Access token stored in Secrets Manager.")
