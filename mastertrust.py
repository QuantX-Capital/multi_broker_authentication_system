import json
import hashlib
import time
from urllib.parse import urlparse, parse_qs

import boto3
import requests

from base_authenticator import BrokerAuthenticator, find_clickable_by_text, find_otp_input


class MasterTrustAuthenticator(BrokerAuthenticator):
    """Handles MasterTrust (Noren) OAuth login, backed by an AWS Secrets Manager secret."""

    LOGIN_URL = "https://midlive.mastertrust.co.in/NorenWeb2.0/authorize/oauth?client_id={client_id}"
    TOKEN_URL = "https://midlive.mastertrust.co.in/NorenWClientAPI/GenAcsTok"

    CREDENTIALS_TIMEOUT = 20
    REDIRECT_TIMEOUT = 600

    def __init__(self, secret_id="/trading/brokers/mastertrust/vaibhav", region_name="ap-south-1"):
        super().__init__()
        self.secret_id = secret_id
        self.client = boto3.client("secretsmanager", region_name=region_name)

        secret = self._get_secret()
        self.client_id = secret.get("client_id")
        self.secret_key = secret["secret_key"]
        self.access_token = secret.get("access_token") or None
        self.user_id = secret.get("user_id") or self.client_id

        if not self.client_id:
            raise ValueError(
                f"'client_id' not found in secret {secret_id!r}. Add it before authenticating."
            )

        self._driver = None

    def _get_secret(self):
        response = self.client.get_secret_value(SecretId=self.secret_id)
        return json.loads(response["SecretString"])

    def _update_secret(self, access_token, refresh_token=None):
        secret = self._get_secret()
        secret["access_token"] = access_token
        if refresh_token:
            secret["refresh_token"] = refresh_token
        self.client.put_secret_value(
            SecretId=self.secret_id,
            SecretString=json.dumps(secret),
        )

    def get_login_url(self):
        return self.LOGIN_URL.format(client_id=self.client_id)

    def exchange_auth_code(self, auth_code):
        """Exchange a MasterTrust authorization code for an access_token and persist it to the secret."""
        checksum = hashlib.sha256(
            (self.client_id + self.secret_key + auth_code).encode("utf-8")
        ).hexdigest()

        jdata = json.dumps({"code": auth_code, "checksum": checksum})

        response = requests.post(
            self.TOKEN_URL,
            data=f"jData={jdata}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        data = response.json()
        if response.status_code != 200 or data.get("stat") != "Ok":
            raise RuntimeError(f"Token exchange failed: {data}")

        access_token = data["access_token"]
        self.access_token = access_token
        self._update_secret(access_token, data.get("refresh_token"))
        return access_token

    def start_login(self, user_id, password, on_status=None):
        """Opens a headless Selenium-driven Chrome and fills in the client ID
        and password. MasterTrust's login page keeps the user ID, password,
        and OTP/TOTP fields on one page throughout - filling in credentials
        doesn't submit anything by itself. A distinct "Get OTP" click tells
        the broker to send the OTP; submit_otp() then fills the OTP field
        and clicks the single "LOGIN" button that submits everything.

        Always returns True: this broker's login always requires an OTP."""
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
                EC.presence_of_element_located((By.ID, "lgnusrid"))
            )
            driver.find_element(By.ID, "lgnusrid").send_keys(user_id)
            driver.find_element(By.ID, "lgnpwd").send_keys(password)

            get_otp_button = find_clickable_by_text(driver, By, "Get OTP")
            if get_otp_button is None:
                raise RuntimeError(
                    "Could not find the 'Get OTP' button on the MasterTrust login page."
                )
            get_otp_button.click()

            self._raise_if_cancelled()
            on_status("waiting_for_otp")
            return True
        except Exception:
            self.abort()
            raise

    def submit_otp(self, otp, on_status=None):
        """Enters the OTP into the already-open login page and waits for the
        redirect containing the authorization code, then exchanges it for an
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
            driver.find_element(By.CLASS_NAME, "lgnBtnClss").click()

            on_status("authenticating")
            return self._finish_from_redirect(driver)
        finally:
            self.abort()

    def _finish_from_redirect(self, driver):
        auth_code = None
        elapsed = 0
        poll_interval = 1
        while elapsed < self.REDIRECT_TIMEOUT:
            self._raise_if_cancelled()
            query = parse_qs(urlparse(driver.current_url).query)
            if "code" in query:
                auth_code = query["code"][0]
                break
            time.sleep(poll_interval)
            elapsed += poll_interval

        if not auth_code:
            raise TimeoutError("Timed out waiting for the login redirect containing the authorization code.")

        return self.exchange_auth_code(auth_code)

    def abort(self):
        if self._driver is not None:
            try:
                self._driver.quit()
            finally:
                self._driver = None

    def get_headers(self):
        if not self.access_token:
            raise RuntimeError("No access token available. Call authenticate() first.")
        return {"Authorization": f"Bearer {self.access_token}"}

    def authenticate(self, on_status=None):
        """Convenience wrapper for local/console use (see __main__ below):
        runs the full login flow using the secret's stored user_id, prompting
        for the password and OTP on the console instead of over the API."""
        import getpass

        password = getpass.getpass(f"MasterTrust password for {self.user_id}: ")
        try:
            otp_required = self.start_login(self.user_id, password, on_status=on_status)
        finally:
            password = None

        if not otp_required:
            return self.access_token

        otp = input("MasterTrust OTP: ")
        try:
            return self.submit_otp(otp, on_status=on_status)
        finally:
            otp = None


if __name__ == "__main__":
    auth = MasterTrustAuthenticator()
    auth.authenticate()
    print("Authenticated. Access token stored in Secrets Manager.")
