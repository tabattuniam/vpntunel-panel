"""VPNTunel Panel — manajemen pelanggan VPN (WireGuard + L2TP)."""
from __future__ import annotations

import hashlib
import logging
import random
import sqlite3
import string
import time
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path

import yaml
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Form, Request, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import TimestampSigner, BadSignature

from storage import Storage
from whatsapp import WuzAPIClient
import wg_manager
import l2tp_manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger(__name__)

cfg = yaml.safe_load(Path("configs/panel.yaml").read_text())

ADMIN_WA         = cfg["admin_wa"]
PAKET_LIST       = cfg["paket"]
DB_PATH          = cfg["db_path"]
BILLING_DB_PATH  = cfg.get("billing_db_path", "")
VPN_DOMAIN       = cfg["frp"]["subdomain_host"]
ADMIN_USER       = cfg["admin"]["username"]
ADMIN_PASS       = cfg["admin"]["password"]
SECRET_KEY       = cfg["admin"]["secret_key"]

signer = TimestampSigner(SECRET_KEY)

storage = Storage(DB_PATH)
wa      = WuzAPIClient(cfg["wuzapi"]["url"], cfg["wuzapi"]["token"])


def is_logged_in(session: str | None) -> bool:
    if not session:
        return False
    try:
        signer.unsign(session, max_age=86400 * 7)  # 7 hari
        return True
    except BadSignature:
        return False


def require_login(session: str | None, redirect: str = "/login") -> RedirectResponse | None:
    if not is_logged_in(session):
        return RedirectResponse(redirect, status_code=302)
    return None


def format_rupiah(n: int) -> str:
    return f"Rp {n:,.0f}".replace(",", ".")

def bulan_ini() -> str:
    return date.today().strftime("%Y-%m")

def gen_pin() -> str:
    return "".join(random.choices(string.digits, k=6))

def gen_l2tp_credentials(subdomain: str) -> tuple[str, str]:
    """Generate username (subdomain) dan password acak."""
    pw = "".join(random.choices(string.ascii_letters + string.digits, k=10))
    return subdomain, pw


# ── Scheduler ────────────────────────────────────────────────────────────────
def cek_jatuh_tempo():
    hari = date.today().day
    bulan = bulan_ini()
    for p in storage.get_jatuh_tempo_hari_ini(hari):
        t = storage.get_or_create_tagihan(p["id"], bulan)
        if t["lunas"]:
            continue
        wa.send(p["nomor_wa"],
            f"Halo {p['nama']},\n\n"
            f"Tagihan VPN bulan ini sebesar *{format_rupiah(p['harga'])}* "
            f"jatuh tempo hari ini.\n\n"
            f"Mohon segera lakukan pembayaran. Terima kasih 🙏"
        )
        wa.send(ADMIN_WA,
            f"⏰ *Jatuh Tempo*\n\nNama: {p['nama']}\nWA: {p['nomor_wa']}\n"
            f"Subdomain: {p['subdomain']}\nTagihan: {format_rupiah(p['harga'])}\nStatus: Belum Bayar"
        )
        log.info("Reminder jatuh tempo: %s", p["nama"])


def _seed_servers():
    """Buat server id1 dari panel.yaml jika tabel servers masih kosong."""
    if storage.list_servers():
        return
    frp = cfg["frp"]
    storage.create_server(
        kode="id1",
        nama="VPS Indonesia 1",
        ip=frp["server_addr"],
        frp_port=frp["server_port"],
        subdomain_host=f"id1.{frp['subdomain_host']}",
        port_start=frp["port_range_start"],
        port_end=frp["port_range_end"],
    )
    log.info("Server id1 di-seed dari panel.yaml")


@asynccontextmanager
async def lifespan(app: FastAPI):
    _seed_servers()
    scheduler = AsyncIOScheduler()
    scheduler.add_job(cek_jatuh_tempo, "cron", hour=8, minute=0)
    scheduler.start()
    yield
    scheduler.shutdown()


app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")
templates.env.globals["format_rupiah"] = format_rupiah
templates.env.globals["bulan_ini"]     = bulan_ini
templates.env.globals["VPN_DOMAIN"]    = VPN_DOMAIN
templates.env.globals["FRP_SUBDOMAIN"] = VPN_DOMAIN  # backward compat


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    return templates.TemplateResponse(request=request, name="login.html", context={"error": ""})


@app.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if username == ADMIN_USER and password == ADMIN_PASS:
        token = signer.sign("admin").decode()
        resp = RedirectResponse("/", status_code=302)
        resp.set_cookie("session", token, httponly=True, samesite="lax", max_age=86400 * 7)
        return resp
    return templates.TemplateResponse(request=request, name="login.html", context={
        "error": "Username atau password salah."
    })


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie("session")
    return resp


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session: str | None = Cookie(default=None)):
    if redir := require_login(session):
        return redir
    bulan = bulan_ini()
    stats = storage.count_stats_full(bulan)
    hari = date.today().day
    jatuh_tempo = storage.get_jatuh_tempo_hari_ini(hari)
    for p in jatuh_tempo:
        t = storage.get_or_create_tagihan(p["id"], bulan)
        p["lunas"] = t["lunas"]
    return templates.TemplateResponse(request=request, name="index.html", context={
        "stats": stats, "jatuh_tempo": jatuh_tempo,
        "hari_ini": date.today().strftime("%d %B %Y"), "bulan": bulan,
    })


@app.get("/tambah", response_class=HTMLResponse)
async def tambah_form(request: Request, session: str | None = Cookie(default=None)):
    if redir := require_login(session):
        return redir
    servers = storage.list_servers()
    return templates.TemplateResponse(request=request, name="tambah.html", context={
        "paket_list": PAKET_LIST, "today": date.today().isoformat(),
        "servers": servers,
    })


@app.post("/tambah")
async def tambah_submit(
    request: Request,
    session: str | None = Cookie(default=None),
    nama: str = Form(...),
    nomor_wa: str = Form(...),
    subdomain: str = Form(...),
    paket: str = Form(...),
    protocol: str = Form("wireguard"),
    tanggal_bayar: int = Form(...),
    tanggal_mulai: str = Form(...),
    catatan: str = Form(""),
    server_id: int = Form(0),
):
    if redir := require_login(session):
        return redir
    servers = storage.list_servers()
    subdomain = subdomain.lower().strip().replace(" ", "")
    if storage.subdomain_exists(subdomain):
        return templates.TemplateResponse(request=request, name="tambah.html", context={
            "paket_list": PAKET_LIST, "today": date.today().isoformat(), "servers": servers,
            "error": f"Subdomain '{subdomain}' sudah digunakan.",
        })

    paket_data = next((p for p in PAKET_LIST if p["name"] == paket), None)
    if not paket_data:
        return templates.TemplateResponse(request=request, name="tambah.html", context={
            "paket_list": PAKET_LIST, "today": date.today().isoformat(), "servers": servers,
            "error": "Paket tidak valid.",
        })

    # Pilih server: manual atau auto (yang paling sedikit pelanggannya)
    if server_id and storage.get_server(server_id):
        assigned_server = storage.get_server(server_id)
    else:
        assigned_server = storage.get_best_server()
    assigned_server_id = assigned_server["id"] if assigned_server else 1

    pin = gen_pin()
    wg_priv = wg_pub = vpn_ip = l2tp_user = l2tp_pass = ""

    if protocol == "wireguard":
        wg_priv, wg_pub = wg_manager.gen_keypair()
        vpn_ip = storage.assign_next_vpn_ip()
        script = wg_manager.generate_client_script(subdomain, wg_priv, vpn_ip)
        script_label = "WireGuard (RouterOS 7.x)"
    else:
        l2tp_user, l2tp_pass = gen_l2tp_credentials(subdomain)
        l2tp_manager.add_user(l2tp_user, l2tp_pass)
        script = l2tp_manager.generate_client_script(l2tp_user, l2tp_pass)
        script_label = "L2TP/IPSec (semua RouterOS)"

    # Assign 4 FRP TCP ports (SSH, WebFig, Winbox, API)
    frp_ports: list[int] = []
    try:
        frp_ports = storage.get_next_ports(assigned_server_id, 4)
    except Exception as e:
        log.warning("Gagal assign FRP ports: %s", e)

    pid = storage.create(
        nama, nomor_wa, subdomain, frp_ports, paket, paket_data["harga"],
        tanggal_bayar, tanggal_mulai, catatan, pin, protocol,
        wg_priv, wg_pub, vpn_ip, l2tp_user, l2tp_pass,
        server_id=assigned_server_id
    )

    if protocol == "wireguard":
        try:
            wg_manager.add_peer(wg_pub, vpn_ip)
        except Exception as e:
            log.error("Gagal add WG peer: %s", e)

    # Create first VPN connection entry
    storage.create_vpn_connection(
        pid, "VPN 1", protocol,
        wg_priv, wg_pub, vpn_ip, l2tp_user, l2tp_pass
    )

    # Register FRP ports to port_usage
    if frp_ports:
        storage.assign_ports(pid, frp_ports, ["ssh", "webfig", "winbox", "api"])

    server_domain = assigned_server["subdomain_host"] if assigned_server else VPN_DOMAIN
    tunnel_url = f"{subdomain}.{server_domain}"
    wa.send(nomor_wa,
        f"Halo {nama}! 🎉\n\n"
        f"Akun VPN Remote MikroTik Anda telah aktif!\n\n"
        f"📦 Paket: {paket}\n"
        f"🔧 Protokol: {script_label}\n"
        f"🌐 Server: {server_domain}\n"
        f"🔗 Tunnel: {tunnel_url}\n"
        f"💰 Tagihan: {format_rupiah(paket_data['harga'])}/bulan\n"
        f"📅 Jatuh tempo: tgl {tanggal_bayar} setiap bulan\n\n"
        f"🔐 *Login Portal:*\n"
        f"URL: https://vpntunel.my.id/login\n"
        f"No WA: {nomor_wa}\n"
        f"PIN: *{pin}*\n\n"
        f"Script konfigurasi akan dikirim terpisah."
    )
    wa.send(nomor_wa,
        f"*Script {script_label}:*\n\n"
        f"Paste di terminal MikroTik (Winbox > New Terminal):\n\n"
        f"```\n{script}\n```"
    )
    wa.send(ADMIN_WA,
        f"✅ *Pelanggan VPN Baru*\n\nNama: {nama}\nWA: {nomor_wa}\n"
        f"Subdomain: {subdomain}\nPaket: {paket}\nProtokol: {protocol}"
    )

    return RedirectResponse(f"/pelanggan?added={pid}", status_code=303)


@app.get("/pelanggan", response_class=HTMLResponse)
async def daftar(request: Request, added: str = "", session: str | None = Cookie(default=None)):
    if redir := require_login(session):
        return redir
    bulan = bulan_ini()
    rows = storage.list_all()
    for r in rows:
        t = storage.get_or_create_tagihan(r["id"], bulan)
        r["lunas"] = t["lunas"]
    return templates.TemplateResponse(request=request, name="pelanggan.html", context={
        "rows": rows, "bulan": bulan, "added": added,
    })


@app.get("/tagihan", response_class=HTMLResponse)
async def tagihan(request: Request, bulan: str = "", session: str | None = Cookie(default=None)):
    if redir := require_login(session):
        return redir
    bulan = bulan or bulan_ini()
    rows = storage.get_tagihan_bulan(bulan)
    stats = storage.count_stats(bulan)
    return templates.TemplateResponse(request=request, name="tagihan.html", context={
        "rows": rows, "bulan": bulan, "stats": stats,
    })


def _gen_frp_conf(p: dict, server: dict, frp_token: str) -> str:
    """Generate FRP client .ini config untuk pelanggan."""
    ports = p.get("ports") or []
    sub   = p["subdomain"]
    ip    = p.get("vpn_ip") or "192.168.88.1"
    srv_ip = server["ip"]
    srv_port = server["frp_port"]
    lines = [
        "[common]",
        f"server_addr = {srv_ip}",
        f"server_port = {srv_port}",
        f"token = {frp_token}",
        "",
    ]
    mapping = [("ssh", 22), ("webfig", 80), ("winbox", 8291), ("api", 8728)]
    for i, (label, local_port) in enumerate(mapping):
        if i < len(ports):
            lines += [
                f"[{label}-{sub}]",
                "type = tcp",
                f"local_ip = {ip}",
                f"local_port = {local_port}",
                f"remote_port = {ports[i]}",
                "",
            ]
    return "\n".join(lines)


@app.get("/config/{pid}/frp.ini")
async def download_frp_config(pid: str, session: str | None = Cookie(default=None)):
    if not is_logged_in(session):
        return RedirectResponse("/login", status_code=302)
    p = storage.get(pid)
    if not p:
        return HTMLResponse("Tidak ditemukan", status_code=404)
    server = storage.get_server(p.get("server_id") or 1) or {}
    content = _gen_frp_conf(p, server, cfg["frp"].get("token", ""))
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        content,
        headers={"Content-Disposition": f'attachment; filename="frpc-{p["subdomain"]}.ini"'}
    )


@app.get("/config/{pid}", response_class=HTMLResponse)
async def lihat_config(request: Request, pid: str, session: str | None = Cookie(default=None)):
    if redir := require_login(session):
        return redir
    p = storage.get(pid)
    if not p:
        return HTMLResponse("Tidak ditemukan", status_code=404)
    if p.get("protocol") == "l2tp":
        script = l2tp_manager.generate_client_script(p["l2tp_user"], p["l2tp_password"])
    else:
        script = wg_manager.generate_client_script(p["subdomain"], p["wg_private_key"], p["vpn_ip"])
    server = storage.get_server(p.get("server_id") or 1)
    ports  = p.get("ports") or []
    return templates.TemplateResponse(request=request, name="config.html", context={
        "p": p, "script": script, "server": server, "ports": ports,
    })


@app.post("/kirim-config/{pid}", response_class=JSONResponse)
async def kirim_config(pid: str):
    p = storage.get(pid)
    if not p:
        return JSONResponse({"ok": False, "msg": "Tidak ditemukan."}, status_code=404)
    if p.get("protocol") == "l2tp":
        script = l2tp_manager.generate_client_script(p["l2tp_user"], p["l2tp_password"])
        label = "L2TP/IPSec"
    else:
        script = wg_manager.generate_client_script(p["subdomain"], p["wg_private_key"], p["vpn_ip"])
        label = "WireGuard"
    ok = wa.send(p["nomor_wa"],
        f"*Script {label} — {p['subdomain']}:*\n\n"
        f"Paste di terminal MikroTik (Winbox > New Terminal):\n\n"
        f"```\n{script}\n```"
    )
    return {"ok": ok, "msg": "Script terkirim via WA." if ok else "Gagal kirim WA."}


@app.post("/bayar/{pid}", response_class=JSONResponse)
async def bayar(pid: str, bulan: str = Form("")):
    bulan = bulan or bulan_ini()
    p = storage.get(pid)
    if not p:
        return JSONResponse({"ok": False, "msg": "Tidak ditemukan."}, status_code=404)
    storage.tandai_lunas(pid, bulan)
    wa.send(ADMIN_WA,
        f"💰 *Pembayaran Diterima*\nNama: {p['nama']}\n"
        f"Bulan: {bulan}\nJumlah: {format_rupiah(p['harga'])}"
    )
    return {"ok": True}


@app.post("/nonaktif/{pid}", response_class=JSONResponse)
async def nonaktif(pid: str):
    p = storage.get(pid)
    if not p:
        return JSONResponse({"ok": False}, status_code=404)
    # Remove all VPN connections
    for vc in storage.get_vpn_connections(pid):
        if vc["protocol"] == "wireguard" and vc["wg_public_key"]:
            try:
                wg_manager.remove_peer(vc["wg_public_key"])
            except Exception as e:
                log.error("Gagal remove WG peer: %s", e)
        elif vc["protocol"] == "l2tp" and vc["l2tp_user"]:
            try:
                l2tp_manager.remove_user(vc["l2tp_user"])
            except Exception as e:
                log.error("Gagal remove L2TP user: %s", e)
        storage.update_vpn_connection_status(vc["id"], "nonaktif")
    storage.update_status(pid, "nonaktif")
    return {"ok": True}


@app.get("/pelanggan/{pid}", response_class=HTMLResponse)
async def detail_pelanggan(request: Request, pid: str, session: str | None = Cookie(default=None)):
    if redir := require_login(session):
        return redir
    p = storage.get(pid)
    if not p:
        return HTMLResponse("Tidak ditemukan", status_code=404)
    vpn_connections = storage.get_vpn_connections(pid)
    # Generate script per connection
    for vc in vpn_connections:
        if vc["protocol"] == "l2tp":
            vc["script"] = l2tp_manager.generate_client_script(vc["l2tp_user"], vc["l2tp_password"])
            vc["proto_label"] = "L2TP/IPSec"
        else:
            vc["script"] = wg_manager.generate_client_script(p["subdomain"], vc["wg_private_key"], vc["vpn_ip"])
            vc["proto_label"] = "WireGuard"
    # Paket limit
    paket_data = next((pk for pk in PAKET_LIST if pk["name"] == p["paket"]), {"ports": 1})
    vpn_limit = paket_data["ports"]
    riwayat = storage.get_riwayat_bayar(pid)
    bulan = bulan_ini()
    tagihan = storage.get_or_create_tagihan(pid, bulan)
    server = storage.get_server(p.get("server_id") or 1)
    return templates.TemplateResponse(request=request, name="detail_pelanggan.html", context={
        "p": p, "vpn_connections": vpn_connections, "vpn_limit": vpn_limit,
        "riwayat": riwayat, "bulan": bulan, "tagihan": tagihan,
        "paket_list": PAKET_LIST, "server": server,
    })


@app.post("/edit/{pid}", response_class=HTMLResponse)
async def edit_pelanggan(
    request: Request,
    pid: str,
    session: str | None = Cookie(default=None),
    nama: str = Form(...),
    nomor_wa: str = Form(...),
    tanggal_bayar: int = Form(...),
    catatan: str = Form(""),
):
    if redir := require_login(session):
        return redir
    storage.update_pelanggan(pid, nama, nomor_wa, tanggal_bayar, catatan)
    return RedirectResponse(f"/pelanggan/{pid}?saved=1", status_code=303)


@app.post("/ubah-paket/{pid}", response_class=JSONResponse)
async def ubah_paket(
    pid: str,
    paket: str = Form(...),
    harga_custom: str = Form(""),
):
    p = storage.get(pid)
    if not p:
        return JSONResponse({"ok": False, "msg": "Pelanggan tidak ditemukan."}, status_code=404)
    paket_data = next((pk for pk in PAKET_LIST if pk["name"] == paket), None)
    if not paket_data:
        return JSONResponse({"ok": False, "msg": "Paket tidak valid."})
    harga = int(harga_custom.strip()) if harga_custom.strip().isdigit() else paket_data["harga"]
    vpn_limit = paket_data["ports"]
    storage.update_paket(pid, paket, harga, vpn_limit)
    wa.send(p["nomor_wa"],
        f"Halo {p['nama']}! 📦\n\n"
        f"Paket VPN Anda telah diubah oleh admin.\n\n"
        f"Paket baru: *{paket}*\n"
        f"Slot VPN: {vpn_limit}\n"
        f"Tagihan: Rp {harga:,}/bulan\n\n"
        f"Info lebih lanjut: https://vpntunel.my.id/portal"
    )
    return {"ok": True, "msg": f"Paket diubah ke {paket} (Rp {harga:,}/bln, {vpn_limit} slot VPN). Notif WA terkirim."}


@app.post("/reset-pin/{pid}", response_class=JSONResponse)
async def reset_pin(pid: str):
    p = storage.get(pid)
    if not p:
        return JSONResponse({"ok": False, "msg": "Tidak ditemukan."}, status_code=404)
    new_pin = gen_pin()
    storage.update_pin(pid, new_pin)
    ok = wa.send(p["nomor_wa"],
        f"Halo {p['nama']},\n\n"
        f"PIN login portal Anda telah direset.\n\n"
        f"🔐 PIN baru: *{new_pin}*\n"
        f"URL: https://vpntunel.my.id/login"
    )
    return {"ok": True, "pin": new_pin, "msg": f"PIN baru: {new_pin}. {'Terkirim ke WA.' if ok else 'Gagal kirim WA.'}" }


@app.post("/tambah-vpn/{pid}", response_class=JSONResponse)
async def tambah_vpn(
    pid: str,
    protocol: str = Form("wireguard"),
    label: str = Form(""),
    session: str | None = Cookie(default=None),
):
    p = storage.get(pid)
    if not p:
        return JSONResponse({"ok": False, "msg": "Pelanggan tidak ditemukan."}, status_code=404)
    paket_data = next((pk for pk in PAKET_LIST if pk["name"] == p["paket"]), {"ports": 1})
    vpn_limit = paket_data["ports"]
    current_count = storage.count_vpn_connections(pid)
    if current_count >= vpn_limit:
        return JSONResponse({"ok": False, "msg": f"Limit paket {p['paket']} hanya {vpn_limit} koneksi VPN."})
    auto_label = label.strip() or f"VPN {current_count + 1}"
    wg_priv = wg_pub = vpn_ip = l2tp_user = l2tp_pass = ""
    if protocol == "wireguard":
        wg_priv, wg_pub = wg_manager.gen_keypair()
        vpn_ip = storage.assign_next_vpn_ip()
        script = wg_manager.generate_client_script(p["subdomain"], wg_priv, vpn_ip)
        try:
            wg_manager.add_peer(wg_pub, vpn_ip)
        except Exception as e:
            log.error("Gagal add WG peer: %s", e)
        proto_label = "WireGuard"
    else:
        l2tp_user = f"{p['subdomain']}-{current_count + 1}"
        l2tp_pass = "".join(random.choices(string.ascii_letters + string.digits, k=10))
        l2tp_manager.add_user(l2tp_user, l2tp_pass)
        script = l2tp_manager.generate_client_script(l2tp_user, l2tp_pass)
        proto_label = "L2TP/IPSec"
    vid = storage.create_vpn_connection(
        pid, auto_label, protocol, wg_priv, wg_pub, vpn_ip, l2tp_user, l2tp_pass
    )
    ok = wa.send(p["nomor_wa"],
        f"Halo {p['nama']}! 🎉\n\n"
        f"Koneksi VPN baru telah ditambahkan ke akun Anda.\n\n"
        f"🔧 Protokol: {proto_label}\n"
        f"📛 Label: {auto_label}\n\n"
        f"*Script Konfigurasi:*\n```\n{script}\n```"
    )
    return {"ok": True, "vid": vid, "label": auto_label, "protocol": protocol,
            "script": script, "proto_label": proto_label,
            "msg": f"VPN '{auto_label}' berhasil ditambahkan. {'Script terkirim via WA.' if ok else ''}"}


@app.post("/hapus-vpn/{vid}", response_class=JSONResponse)
async def hapus_vpn(vid: int):
    vc = storage.get_vpn_connection(vid)
    if not vc:
        return JSONResponse({"ok": False, "msg": "Koneksi tidak ditemukan."}, status_code=404)
    if vc["protocol"] == "wireguard" and vc["wg_public_key"]:
        try:
            wg_manager.remove_peer(vc["wg_public_key"])
        except Exception as e:
            log.error("Gagal remove WG peer: %s", e)
    elif vc["protocol"] == "l2tp" and vc["l2tp_user"]:
        try:
            l2tp_manager.remove_user(vc["l2tp_user"])
        except Exception as e:
            log.error("Gagal remove L2TP user: %s", e)
    storage.delete_vpn_connection(vid)
    return {"ok": True, "msg": "Koneksi VPN berhasil dihapus."}


@app.post("/kirim-config-vpn/{vid}", response_class=JSONResponse)
async def kirim_config_vpn(vid: int):
    vc = storage.get_vpn_connection(vid)
    if not vc:
        return JSONResponse({"ok": False, "msg": "Koneksi tidak ditemukan."}, status_code=404)
    p = storage.get(vc["pelanggan_id"])
    if not p:
        return JSONResponse({"ok": False, "msg": "Pelanggan tidak ditemukan."}, status_code=404)
    if vc["protocol"] == "l2tp":
        script = l2tp_manager.generate_client_script(vc["l2tp_user"], vc["l2tp_password"])
        label = "L2TP/IPSec"
    else:
        script = wg_manager.generate_client_script(p["subdomain"], vc["wg_private_key"], vc["vpn_ip"])
        label = "WireGuard"
    ok = wa.send(p["nomor_wa"],
        f"*Script {label} — {vc['label']}:*\n\n"
        f"Paste di terminal MikroTik (Winbox > New Terminal):\n\n"
        f"```\n{script}\n```"
    )
    return {"ok": ok, "msg": "Script terkirim via WA." if ok else "Gagal kirim WA."}


@app.post("/aktifkan/{pid}", response_class=JSONResponse)
async def aktifkan(pid: str):
    p = storage.get(pid)
    if not p:
        return JSONResponse({"ok": False}, status_code=404)
    # Re-activate all VPN connections
    for vc in storage.get_vpn_connections(pid):
        if vc["protocol"] == "wireguard" and vc["wg_public_key"]:
            try:
                wg_manager.add_peer(vc["wg_public_key"], vc["vpn_ip"])
            except Exception as e:
                log.error("Gagal re-add WG peer: %s", e)
        elif vc["protocol"] == "l2tp" and vc["l2tp_user"]:
            try:
                l2tp_manager.add_user(vc["l2tp_user"], vc["l2tp_password"])
            except Exception as e:
                log.error("Gagal re-add L2TP user: %s", e)
        storage.update_vpn_connection_status(vc["id"], "aktif")
    storage.update_status(pid, "aktif")
    return {"ok": True}


# ── Billing Tenant Manager ────────────────────────────────────────────────────

class BillingDB:
    """Thin wrapper untuk akses read/write ke database billing-web."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def _conn(self):
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def list_tenants(self) -> list[dict]:
        con = self._conn()
        rows = con.execute("SELECT * FROM users WHERE role='admin' ORDER BY nama").fetchall()
        con.close()
        return [dict(r) for r in rows]

    def get_tenant(self, uid: str) -> dict | None:
        con = self._conn()
        row = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        con.close()
        return dict(row) if row else None

    def get_tenant_stats(self, uid: str) -> dict:
        con = self._conn()
        pppoe   = con.execute("SELECT COUNT(*) FROM pppoe_users WHERE user_id=? AND status='aktif'", (uid,)).fetchone()[0]
        voucher = con.execute("SELECT COUNT(*) FROM voucher_hotspot WHERE user_id=? AND status='tersedia'", (uid,)).fetchone()[0]
        omzet   = con.execute("SELECT COALESCE(SUM(amount),0) FROM transaksi WHERE user_id=? AND status='paid'", (uid,)).fetchone()[0]
        servers = con.execute("SELECT COUNT(*) FROM mikrotik_servers WHERE user_id=?", (uid,)).fetchone()[0]
        agen    = con.execute("SELECT COUNT(*) FROM users WHERE parent_id=? AND role='agen'", (uid,)).fetchone()[0]
        con.close()
        return {"pppoe": pppoe, "voucher": voucher, "omzet": omzet, "servers": servers, "agen": agen}

    def adjust_saldo(self, uid: str, amount: int, catatan: str) -> dict | None:
        con = self._conn()
        row = con.execute("SELECT saldo FROM users WHERE id=?", (uid,)).fetchone()
        if not row:
            con.close()
            return None
        saldo_before = int(row["saldo"])
        saldo_after  = max(0, saldo_before + amount)
        con.execute("UPDATE users SET saldo=? WHERE id=?", (saldo_after, uid))
        con.execute(
            "INSERT INTO saldo_adjustments (user_id, amount, saldo_before, saldo_after, catatan, by_sa, created_at) VALUES (?,?,?,?,?,1,?)",
            (uid, amount, saldo_before, saldo_after, catatan, int(time.time()))
        )
        con.commit()
        con.close()
        return {"saldo_before": saldo_before, "saldo_after": saldo_after}

    def reset_password(self, uid: str, password: str):
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        con = self._conn()
        con.execute("UPDATE users SET password=? WHERE id=?", (pw_hash, uid))
        con.commit()
        con.close()

    def set_status(self, uid: str, status: str):
        con = self._conn()
        con.execute("UPDATE users SET status=? WHERE id=?", (status, uid))
        con.commit()
        con.close()

    def list_adjustments(self, uid: str = "", limit: int = 50) -> list[dict]:
        con = self._conn()
        if uid:
            rows = con.execute(
                "SELECT sa.*, u.nama, u.username FROM saldo_adjustments sa LEFT JOIN users u ON u.id=sa.user_id WHERE sa.user_id=? ORDER BY sa.created_at DESC LIMIT ?",
                (uid, limit)
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT sa.*, u.nama, u.username FROM saldo_adjustments sa LEFT JOIN users u ON u.id=sa.user_id ORDER BY sa.created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        con.close()
        return [dict(r) for r in rows]


billing_db = BillingDB(BILLING_DB_PATH) if BILLING_DB_PATH else None


def _format_rp(n) -> str:
    try:
        return f"Rp {int(n):,}".replace(",", ".")
    except Exception:
        return str(n)

def _ts_date(ts) -> str:
    from datetime import datetime
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%-d %b %Y %H:%M")
    except Exception:
        return str(ts)


@app.get("/billing", response_class=HTMLResponse)
async def billing_dashboard(request: Request, session: str | None = Cookie(None)):
    redir = require_login(session)
    if redir:
        return redir
    if not billing_db:
        return HTMLResponse("<h2>billing_db_path belum dikonfigurasi di panel.yaml</h2>", status_code=500)
    tenants     = billing_db.list_tenants()
    stats       = {t["id"]: billing_db.get_tenant_stats(t["id"]) for t in tenants}
    adjustments = billing_db.list_adjustments(limit=30)
    return templates.TemplateResponse(request, "billing_tenants.html", {
        "request": request, "tenants": tenants, "stats": stats,
        "adjustments": adjustments, "format_rp": _format_rp, "ts_date": _ts_date,
    })


@app.post("/billing/tenant/{uid}/adjust-saldo", response_class=JSONResponse)
async def billing_adjust_saldo(uid: str, amount: int = Form(0), catatan: str = Form(""),
                                session: str | None = Cookie(None)):
    if not is_logged_in(session):
        return JSONResponse({"ok": False, "msg": "Unauthorized"}, status_code=401)
    if not billing_db or amount == 0:
        return JSONResponse({"ok": False, "msg": "Jumlah tidak boleh 0"})
    result = billing_db.adjust_saldo(uid, amount, catatan)
    if not result:
        return JSONResponse({"ok": False, "msg": "Tenant tidak ditemukan"})
    return JSONResponse({"ok": True, "saldo_before": result["saldo_before"], "saldo_after": result["saldo_after"]})


@app.post("/billing/tenant/{uid}/reset-password")
async def billing_reset_password(uid: str, password: str = Form(""),
                                  session: str | None = Cookie(None)):
    if not is_logged_in(session):
        return RedirectResponse("/login", status_code=302)
    if not billing_db or len(password) < 6:
        return RedirectResponse("/billing?error=password_terlalu_pendek", status_code=302)
    billing_db.reset_password(uid, password)
    return RedirectResponse("/billing?ok=password_direset", status_code=302)


@app.post("/billing/tenant/{uid}/status")
async def billing_toggle_status(uid: str, status: str = Form(""),
                                 session: str | None = Cookie(None)):
    if not is_logged_in(session):
        return RedirectResponse("/login", status_code=302)
    if not billing_db or status not in ("aktif", "nonaktif"):
        return RedirectResponse("/billing", status_code=302)
    billing_db.set_status(uid, status)
    return RedirectResponse("/billing?ok=status_diubah", status_code=302)


@app.get("/billing/tenant/{uid}/adjustments", response_class=JSONResponse)
async def billing_tenant_adjustments(uid: str, session: str | None = Cookie(None)):
    if not is_logged_in(session):
        return JSONResponse({"ok": False}, status_code=401)
    if not billing_db:
        return JSONResponse([])
    rows = billing_db.list_adjustments(uid=uid, limit=50)
    return JSONResponse(rows)


# ── VPN Status Monitor ───────────────────────────────────────────────────────

@app.get("/api/vpn-status", response_class=JSONResponse)
async def api_vpn_status(session: str | None = Cookie(default=None)):
    if not is_logged_in(session):
        return JSONResponse({"ok": False}, status_code=401)
    wg_peers = wg_manager.get_peers_status()
    l2tp_active = list(l2tp_manager.get_active_users())
    return JSONResponse({"ok": True, "wg": wg_peers, "l2tp": l2tp_active})


# ── Server Management ─────────────────────────────────────────────────────────

@app.get("/servers", response_class=HTMLResponse)
async def daftar_servers(request: Request, session: str | None = Cookie(default=None)):
    if redir := require_login(session):
        return redir
    servers = storage.list_servers()
    for s in servers:
        s["jumlah_pelanggan"] = storage.count_pelanggan_by_server(s["id"])
    return templates.TemplateResponse(request=request, name="servers.html", context={
        "servers": servers,
    })


@app.post("/servers/tambah", response_class=HTMLResponse)
async def tambah_server(
    request: Request,
    session: str | None = Cookie(default=None),
    kode: str = Form(...),
    nama: str = Form(...),
    ip: str = Form(...),
    frp_port: int = Form(7000),
    port_start: int = Form(10000),
    port_end: int = Form(20000),
):
    if redir := require_login(session):
        return redir
    kode = kode.lower().strip().replace(" ", "")
    subdomain_host = f"{kode}.vpntunel.my.id"
    storage.create_server(kode, nama, ip, frp_port, subdomain_host, port_start, port_end)
    log.info("Server baru ditambah: %s (%s)", kode, ip)
    return RedirectResponse("/servers?ok=1", status_code=303)


@app.post("/servers/hapus/{sid}", response_class=JSONResponse)
async def hapus_server(sid: int, session: str | None = Cookie(default=None)):
    if not is_logged_in(session):
        return JSONResponse({"ok": False}, status_code=401)
    jumlah = storage.count_pelanggan_by_server(sid)
    if jumlah > 0:
        return JSONResponse({"ok": False, "msg": f"Server masih memiliki {jumlah} pelanggan aktif."})
    storage.delete_server(sid)
    return JSONResponse({"ok": True})


@app.post("/pelanggan/{pid}/pindah-server", response_class=JSONResponse)
async def pindah_server(pid: str, server_id: int = Form(...),
                         session: str | None = Cookie(default=None)):
    if not is_logged_in(session):
        return JSONResponse({"ok": False}, status_code=401)
    p = storage.get(pid)
    if not p:
        return JSONResponse({"ok": False, "msg": "Pelanggan tidak ditemukan."}, status_code=404)
    server = storage.get_server(server_id)
    if not server:
        return JSONResponse({"ok": False, "msg": "Server tidak ditemukan."})
    storage.update_pelanggan_server(pid, server_id)
    return JSONResponse({"ok": True, "msg": f"Pelanggan dipindah ke server {server['kode']}. DNS dan konfigurasi MikroTik perlu diperbarui."})
