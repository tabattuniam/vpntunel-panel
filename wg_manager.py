"""WireGuard peer manager — add/remove peers dari wg0."""
from __future__ import annotations
import subprocess


WG_IFACE    = "wg0"
WG_CONF     = "/etc/wireguard/wg0.conf"
SERVER_PUBKEY = "9uDzjHO+D/mbtDdqFy7yeA76XFNERkLHmcCfxTtWHSs="
SERVER_ADDR   = "103.93.162.154"
SERVER_PORT   = 51820
DNS           = "8.8.8.8"


def gen_keypair() -> tuple[str, str]:
    """Return (private_key, public_key)."""
    priv = subprocess.check_output(["wg", "genkey"]).decode().strip()
    pub  = subprocess.check_output(["wg", "pubkey"], input=priv.encode()).decode().strip()
    return priv, pub


def add_peer(public_key: str, vpn_ip: str):
    """Tambah peer ke wg0 (live + persistent)."""
    subprocess.run(
        ["sudo", "wg", "set", WG_IFACE, "peer", public_key,
         "allowed-ips", f"{vpn_ip}/32"],
        check=True
    )
    subprocess.run(["sudo", "wg-quick", "save", WG_IFACE], check=True)


def remove_peer(public_key: str):
    """Hapus peer dari wg0."""
    subprocess.run(
        ["sudo", "wg", "set", WG_IFACE, "peer", public_key, "remove"],
        check=True
    )
    subprocess.run(["sudo", "wg-quick", "save", WG_IFACE], check=True)


def generate_client_script(subdomain: str, private_key: str, vpn_ip: str) -> str:
    """Script MikroTik RouterOS 7.x untuk pasang WireGuard client."""
    return (
        f"/interface wireguard add name=vpntunel-{subdomain} listen-port=13231 "
        f"private-key=\"{private_key}\"\n"
        f"/ip address add address={vpn_ip}/24 interface=vpntunel-{subdomain}\n"
        f"/interface wireguard peers add interface=vpntunel-{subdomain} "
        f"public-key=\"{SERVER_PUBKEY}\" "
        f"endpoint-address={SERVER_ADDR} endpoint-port={SERVER_PORT} "
        f"allowed-address=0.0.0.0/0 persistent-keepalive=25"
    )
