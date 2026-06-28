"""L2TP/IPSec user manager — tambah/hapus user di chap-secrets."""
from __future__ import annotations
import subprocess

CHAP_SECRETS = "/etc/ppp/chap-secrets"
SERVER_NAME  = "vpntunel"
SERVER_ADDR  = "103.93.162.154"
PSK          = "vpntunel2024ipsec"


def _read_chap() -> str:
    return subprocess.check_output(["sudo", "cat", CHAP_SECRETS]).decode()


def _write_chap(content: str):
    proc = subprocess.Popen(["sudo", "tee", CHAP_SECRETS],
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL)
    proc.communicate(content.encode())


def add_user(username: str, password: str):
    content = _read_chap()
    if username not in content:
        line = f'{username}\t{SERVER_NAME}\t{password}\t*\n'
        _write_chap(content + line)


def remove_user(username: str):
    content = _read_chap()
    lines = [l for l in content.splitlines(keepends=True)
             if not (l.startswith(username + "\t") or l.startswith(username + " "))]
    _write_chap("".join(lines))


def get_active_users() -> set[str]:
    """Cek user L2TP yang sedang terkoneksi via interface ppp aktif."""
    active: set[str] = set()
    try:
        # Cari semua interface ppp yang UP
        out = subprocess.check_output(
            ["ip", "-o", "link", "show", "type", "ppp", "up"],
            stderr=subprocess.DEVNULL
        ).decode()
        ppp_ifaces = [line.split(":")[1].strip() for line in out.strip().split("\n") if line]
        if not ppp_ifaces:
            return active
        # Baca journal xl2tpd untuk username terakhir per interface
        try:
            journal = subprocess.check_output(
                ["journalctl", "-u", "xl2tpd", "-u", "ppp*", "--since", "12 hours ago",
                 "--no-pager", "-q", "-o", "cat"],
                stderr=subprocess.DEVNULL
            ).decode()
            for line in journal.split("\n"):
                if "Connect:" in line or "logged in" in line or "PPP connect" in line:
                    parts = line.lower().split()
                    for i, p in enumerate(parts):
                        if p in ("user", "connect:") and i + 1 < len(parts):
                            active.add(parts[i + 1].strip(".,"))
        except Exception:
            pass
        # Jika ada ppp interface aktif tapi tidak bisa identifikasi user — tandai ada koneksi
        if ppp_ifaces and not active:
            active.add("__unknown__")
    except Exception:
        pass
    return active


def generate_client_script(username: str, password: str) -> str:
    return (
        f"/interface l2tp-client add name=vpntunel connect-to={SERVER_ADDR} "
        f"user={username} password={password} "
        f"use-ipsec=yes ipsec-secret={PSK} disabled=no"
    )
