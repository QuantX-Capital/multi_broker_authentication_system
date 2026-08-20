#!/usr/bin/env bash
# One-time EC2 setup: Ubuntu 22.04/24.04. Installs Chrome, a virtual display,
# and a noVNC viewer so the OTP step can be completed remotely through a browser tab.
set -euo pipefail

sudo apt-get update
sudo apt-get install -y wget unzip python3-venv xvfb x11vnc novnc websockify

# Google Chrome (not in the default apt repos)
wget -O /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt-get install -y /tmp/chrome.deb

echo "Done. Chrome, Xvfb, x11vnc, and noVNC are installed."
echo
echo "Next steps:"
echo "  1. Set a VNC password (interactive, run once):"
echo "       sudo x11vnc -storepasswd /etc/x11vnc.pass"
echo "  2. Copy the systemd unit files from deploy/ into /etc/systemd/system/"
echo "  3. sudo systemctl enable --now xvfb x11vnc novnc broker-auth"
echo "  4. Open http://<ec2-ip>:6080/vnc.html to watch/interact with the browser during login"
