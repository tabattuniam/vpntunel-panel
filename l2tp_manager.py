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


def generate_client_script(username: str, password: str) -> str:
    return (
        f"/interface l2tp-client add name=vpntunel connect-to={SERVER_ADDR} "
        f"user={username} password={password} "
        f"use-ipsec=yes ipsec-secret={PSK} disabled=no"
    )
