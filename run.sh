#!/usr/bin/env bash
# Launcher: starts NmapGUI as root (needed for SYN, UDP, OS and ARP scans).
cd "$(dirname "$0")" || exit 1
if [ "$(id -u)" -ne 0 ]; then exec sudo -E python3 nmap_gui.py "$@"; fi
exec python3 nmap_gui.py "$@"
