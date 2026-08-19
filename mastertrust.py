import json
import hashlib
import time
from urllib.parse import urlparse, parse_qs

import boto3
import requests

from base_authenticator import BrokerAuthenticator


class MasterTrustAuthenticator(BrokerAuthenticator):
    """Handles MasterTrust (Noren) OAuth login, backed by an AWS Secrets Manager secret."""

    LOGIN_URL = "https://midlive.mastertrust.co.in/NorenWeb2.0/authorize/oauth?client_id={client_id}"
    TOKEN_URL = "https://midlive.mastertrust.co.in/NorenWClientAPI/GenAcsTok"

    def __init__(self, secret_id="/trading/brokers/mastertrust/vaibhav", region_name="ap-south-1"):
        self.secret_id = secret_id
        self.client = boto3.client("secretsmanager", region_name=region_name)

        secret = self._get_secret()
        self.client_id = secret.get("client_id")
        self.secret_key = secret["secret_key"]
        self.access_token = secret.get("access_token") or None
        self.user_id = secret.get("user_id") or self.client_id
        self.password = secret.get("password")

        if not self.client_id:
            raise ValueError(
                f"'client_id' not found in secret {secret_id!r}. Add it before authenticating."
            )

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

    def login_via_browser(self, timeout=180, poll_interval=1):
        """Opens a Selenium-driven browser, auto-fills the client ID/password if
        available, and waits for you to complete the OTP step. Once MasterTrust
        redirects back with an authorization code in the URL, it's captured
        automatically and exchanged for an access token."""
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC

        driver = webdriver.Chrome()
        try:
            driver.get(self.get_login_url())

            if self.user_id and self.password:
                WebDriverWait(driver, 20).until(
                    EC.presence_of_element_located((By.ID, "lgnusrid"))
                )
                driver.find_element(By.ID, "lgnusrid").send_keys(self.user_id)
                driver.find_element(By.ID, "lgnpwd").send_keys(self.password)
                driver.find_element(By.CLASS_NAME, "lgnBtnClss").click()

            auth_code = None
            elapsed = 0
            while elapsed < timeout:
                query = parse_qs(urlparse(driver.current_url).query)
                if "code" in query:
                    auth_code = query["code"][0]
                    break
                time.sleep(poll_interval)
                elapsed += poll_interval

            if not auth_code:
                raise TimeoutError("Timed out waiting for the login redirect containing the authorization code.")
        finally:
            driver.quit()

        return self.exchange_auth_code(auth_code)

    def get_headers(self):
        if not self.access_token:
            raise RuntimeError("No access token available. Call authenticate() first.")
        return {"Authorization": f"Bearer {self.access_token}"}

    def authenticate(self):
        """Always runs the full browser login flow."""
        return self.login_via_browser()


if __name__ == "__main__":
    auth = MasterTrustAuthenticator()
    auth.authenticate()
    print("Access token:", auth.access_token)
