# MTU Finder for WireGuard (Windows)

Small Tk GUI tool to discover your path MTU and suggest a WireGuard‑friendly MTU.

## What it does
- Pings a host with DF flag and binary‑searches the largest size that doesn’t fragment.
- Shows:
  - Default interface MTU
  - Path MTU
  - Recommended MTU for VPN

## Download
Grab the `.exe` from the **Releases** page (tagged versions) or the **Nightly** prerelease.
