#!/usr/bin/env bash
# One-time EC2 setup: Ubuntu 22.04/24.04. Installs Chrome, a virtual display,
# and a noVNC viewer so the OTP step can be completed remotely, embedded in the
# web app - not through a separate :6080 tab.
set -euo pipefail

sudo apt-get update
sudo apt-get install -y wget unzip python3-venv xvfb x11vnc novnc websockify

# Google Chrome (not in the default apt repos)
wget -O /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt-get install -y /tmp/chrome.deb

echo "Done. Chrome, Xvfb, x11vnc, and noVNC are installed."
echo
echo "Next steps:"
echo "  1. Copy the systemd unit files from deploy/ into /etc/systemd/system/"
echo "  2. sudo systemctl daemon-reload && sudo systemctl enable --now xvfb x11vnc novnc broker-auth"
echo "  3. Merge deploy/nginx-broker-auth.conf's location blocks into your existing"
echo "     Nginx site config, then: sudo nginx -t && sudo systemctl reload nginx"
echo "  4. Confirm ports 6080/5900/8000 are NOT open in the EC2 security group -"
echo "     only 22 (your IP), 80, and 443 should be public"
echo "  5. Open https://<your-domain> and use Authenticate as normal - the browser"
echo "     view now appears embedded in the page, no separate :6080 tab needed"
