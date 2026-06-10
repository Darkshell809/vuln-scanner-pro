#!/bin/bash

echo "[*] Installing System Dependencies..."
sudo apt update
sudo apt install -y nmap nuclei nikto python3-pip

echo "[*] Installing Python Dependencies..."
pip3 install -r requirements.txt

echo "[*] Installing Playwright Browser..."
python3 -m playwright install chromium

echo "[+] Setup Complete!"
