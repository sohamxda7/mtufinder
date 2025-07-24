#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# WireGuard MTU Finder (Windows only)
# Copyright (C) 2025
#   Soham Sen <sohamsen2000@outlook.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import platform
import subprocess
import re
import threading
import socket
import tkinter as tk
from tkinter import ttk, messagebox

# ---------- Meta ----------
VERSION = "1.0"
AUTHOR  = "Soham Sen"

# ---------- Config ----------
DEFAULT_HOST = "1.1.1.1"
WG_HEADROOM  = 80           # subtract for WG/OpenVPN/UDP overhead
PING_TRIES   = 2
TIMEOUT_MS   = 1500         # ms

FRAG_PATTERNS = [
    "Packet needs to be fragmented",
    "fragmentation needed",
]
SUCCESS_PATTERN = re.compile(r"TTL=\d+", re.I)

# ---------- Subprocess console hiding (Windows) ----------
if platform.system().lower() == "windows":
    CREATE_NO_WINDOW = 0x08000000
    STARTUPINFO = subprocess.STARTUPINFO()
    STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW
else:
    CREATE_NO_WINDOW = 0
    STARTUPINFO = None

def _check_output_silent(args):
    """Run subprocess.check_output without flashing a console window."""
    return subprocess.check_output(
        args,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="ignore",
        startupinfo=STARTUPINFO,
        creationflags=CREATE_NO_WINDOW
    )

# ---------- Helpers ----------
def is_windows():
    return platform.system().lower() == "windows"

def resolve_ipv4(host: str) -> str:
    """Return first IPv4 for host, or the original if already IPv4."""
    try:
        socket.inet_aton(host)  # already IPv4
        return host
    except OSError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except socket.gaierror:
        pass
    return host  # let ping fail; we'll catch it

def ping_ok(host: str, size: int) -> bool:
    # Force IPv4 (-4) so DF works
    args = ["ping", "-4", "-f", "-l", str(size), "-n", "1", "-w", str(TIMEOUT_MS), host]
    try:
        out = _check_output_silent(args)
    except subprocess.CalledProcessError as e:
        out = e.output

    if any(pat.lower() in out.lower() for pat in FRAG_PATTERNS):
        return False
    return bool(SUCCESS_PATTERN.search(out))

def find_path_mtu(host: str) -> int:
    # payload sizes (IP+ICMP header ~28 bytes)
    low, high = 0, 1472
    best = 0
    while low <= high:
        mid = (low + high) // 2
        ok = sum(ping_ok(host, mid) for _ in range(PING_TRIES)) == PING_TRIES
        if ok:
            best = mid
            low = mid + 1
        else:
            high = mid - 1
    return best + 28

def get_default_interface_mtu() -> int | None:
    try:
        out = _check_output_silent(
            ["netsh", "interface", "ipv4", "show", "subinterfaces"]
        )
    except Exception:
        return None

    lines = out.splitlines()
    data_lines = [l for l in lines if re.search(r"\d+\s+\d+\s+\d+\s+\d+\s+.+", l)]
    best_bytes_in = -1
    best_mtu = None
    for l in data_lines:
        parts = l.split()
        if len(parts) < 5:
            continue
        try:
            mtu = int(parts[0])
            bytes_in = int(parts[2])
        except ValueError:
            continue
        if bytes_in > best_bytes_in:
            best_bytes_in = bytes_in
            best_mtu = mtu
    return best_mtu

# ---------- GUI ----------
class MTUApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WireGuard MTU Finder")
        self.resizable(False, False)

        self.host_var     = tk.StringVar(value=DEFAULT_HOST)
        self.status_var   = tk.StringVar(value="Ready to find")
        self.path_mtu_var = tk.StringVar(value="-")
        self.vpn_mtu_var  = tk.StringVar(value="-")
        self.if_mtu_var   = tk.StringVar(value="-")

        self._build_ui()
        self._populate_interface_mtu()

    def _build_ui(self):
        pad = {'padx': 10, 'pady': 5}
        frm = ttk.Frame(self)
        frm.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frm, text="Test host:").grid(row=0, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.host_var, width=18).grid(row=0, column=1, sticky="w", **pad)
        ttk.Button(frm, text="Find MTU", command=self.start_measure).grid(row=0, column=2, **pad)

        ttk.Separator(frm, orient="horizontal").grid(row=1, column=0, columnspan=3, sticky="ew", pady=(5,5))

        ttk.Label(frm, text="Default IF MTU:").grid(row=2, column=0, sticky="e", **pad)
        ttk.Label(frm, textvariable=self.if_mtu_var).grid(row=2, column=1, sticky="w", **pad)

        ttk.Label(frm, text="Path MTU:").grid(row=3, column=0, sticky="e", **pad)
        ttk.Label(frm, textvariable=self.path_mtu_var).grid(row=3, column=1, sticky="w", **pad)

        ttk.Label(frm, text="Optimal MTU for VPN:").grid(row=4, column=0, sticky="e", **pad)
        ttk.Label(frm, textvariable=self.vpn_mtu_var).grid(row=4, column=1, sticky="w", **pad)

        ttk.Separator(frm, orient="horizontal").grid(row=5, column=0, columnspan=3, sticky="ew", pady=(5,5))

        ttk.Label(frm, textvariable=self.status_var, foreground="#555").grid(
            row=6, column=0, columnspan=3, sticky="w", padx=10, pady=(0,5)
        )

        ttk.Separator(frm, orient="horizontal").grid(row=7, column=0, columnspan=3, sticky="ew", pady=(0,3))

        footer = f"Version {VERSION}  ·  {AUTHOR}"
        ttk.Label(frm, text=footer, foreground="#666").grid(
            row=8, column=0, columnspan=3, sticky="e", padx=10, pady=(0,8)
        )

    def _populate_interface_mtu(self):
        mtu = get_default_interface_mtu()
        if mtu:
            self.if_mtu_var.set(str(mtu))

    def start_measure(self):
        if not is_windows():
            messagebox.showerror("Nope", "This tool is Windows-only.")
            return

        host_in = self.host_var.get().strip()
        if not host_in:
            messagebox.showwarning("Host?", "Enter a host/IP to ping.")
            return

        resolved = resolve_ipv4(host_in)

        self.status_var.set("Measuring…")
        self.path_mtu_var.set("-")
        self.vpn_mtu_var.set("-")

        threading.Thread(target=self._measure_thread, args=(resolved,), daemon=True).start()

    def _measure_thread(self, host):
        try:
            path_mtu = find_path_mtu(host)
            vpn_mtu = max(path_mtu - WG_HEADROOM, 576)
            self.after(0, self._update_results, path_mtu, vpn_mtu)
        except Exception as e:
            self.after(0, self._show_error, e)

    def _update_results(self, path_mtu: int, vpn_mtu: int) -> None:
        self.path_mtu_var.set(str(path_mtu))
        self.vpn_mtu_var.set(str(vpn_mtu))
        self.status_var.set("Done.")

    def _show_error(self, err: Exception) -> None:
        self.status_var.set("Error.")
        messagebox.showerror("Error", str(err))

def main():
    if not is_windows():
        print("Windows only.")
        return
    app = MTUApp()
    app.mainloop()

if __name__ == "__main__":
    main()
