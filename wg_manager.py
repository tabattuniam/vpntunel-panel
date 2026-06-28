"""WireGuard peer manager — add/remove peers dari wg0."""
from __future__ import annotations
import subprocess
import time


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


def get_peers_status() -> dict[str, dict]:
    """Parse 'wg show wg0 dump' → {public_key: {online, handshake_ago, endpoint, rx, tx}}."""
    try:
        out = subprocess.check_output(
            ["sudo", "wg", "show", "wg0", "dump"],
            stderr=subprocess.DEVNULL
        ).decode()
        now = int(time.time())
        peers: dict[str, dict] = {}
        for line in out.strip().split("\n")[1:]:  # baris pertama = server config
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            pub_key      = parts[0]
            endpoint     = parts[2] if parts[2] != "(none)" else None
            handshake_ts = int(parts[4]) if parts[4].isdigit() else 0
            rx_bytes     = int(parts[5]) if parts[5].isdigit() else 0
            tx_bytes     = int(parts[6].rstrip()) if parts[6].strip().isdigit() else 0
            ago          = now - handshake_ts if handshake_ts else None
            online       = handshake_ts > 0 and ago is not None and ago < 180
            peers[pub_key] = {
                "online":        online,
                "handshake_ts":  handshake_ts,
                "handshake_ago": ago,
                "endpoint":      endpoint,
                "rx_bytes":      rx_bytes,
                "tx_bytes":      tx_bytes,
            }
        return peers
    except Exception:
        return {}


def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


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
