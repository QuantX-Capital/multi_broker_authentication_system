#!/usr/bin/env bash
# One-time EC2 setup: Ubuntu 22.04/24.04. Installs Chrome and Chromedriver
# requirements for headless Selenium - no virtual display or VNC needed since
# Chrome runs invisibly on the box.
set -euo pipefail

sudo apt-get update
sudo apt-get install -y wget unzip python3-venv

# Google Chrome (not in the default apt repos)
wget -O /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt-get install -y /tmp/chrome.deb

echo "Done. Chrome is installed."
echo
echo "Next steps:"
echo "  1. Copy deploy/broker-auth.service into /etc/systemd/system/"
echo "  2. sudo systemctl daemon-reload && sudo systemctl enable --now broker-auth"
echo "  3. Merge deploy/nginx-broker-auth.conf's location block into your existing"
echo "     Nginx site config, then: sudo nginx -t && sudo systemctl reload nginx"
echo "  4. Confirm only 22 (your IP), 80, and 443 are public in the EC2 security"
echo "     group - port 8000 should NOT be open"
echo "  5. Open https://<your-domain> and use Authenticate as normal - Chrome runs"
echo "     headlessly on the server, nothing is shown to the user"
