"""VPNTunel Panel — manajemen pelanggan VPN (WireGuard + L2TP)."""
from __future__ import annotations

import hashlib
import logging
import random
import string
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

ADMIN_WA    = cfg["admin_wa"]
PAKET_LIST  = cfg["paket"]
DB_PATH     = cfg["db_path"]
VPN_DOMAIN  = cfg["frp"]["subdomain_host"]
ADMIN_USER  = cfg["admin"]["username"]
ADMIN_PASS  = cfg["admin"]["password"]
SECRET_KEY  = cfg["admin"]["secret_key"]

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


@asynccontextmanager
async def lifespan(app: FastAPI):
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
    return templates.TemplateResponse(request=request, name="tambah.html", context={
        "paket_list": PAKET_LIST, "today": date.today().isoformat(),
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
):
    if redir := require_login(session):
        return redir
    subdomain = subdomain.lower().strip().replace(" ", "")
    if storage.subdomain_exists(subdomain):
        return templates.TemplateResponse(request=request, name="tambah.html", context={
            "paket_list": PAKET_LIST, "today": date.today().isoformat(),
            "error": f"Subdomain '{subdomain}' sudah digunakan.",
        })

    paket_data = next((p for p in PAKET_LIST if p["name"] == paket), None)
    if not paket_data:
        return templates.TemplateResponse(request=request, name="tambah.html", context={
            "paket_list": PAKET_LIST, "today": date.today().isoformat(),
            "error": "Paket tidak valid.",
        })

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

    pid = storage.create(
        nama, nomor_wa, subdomain, [], paket, paket_data["harga"],
        tanggal_bayar, tanggal_mulai, catatan, pin, protocol,
        wg_priv, wg_pub, vpn_ip, l2tp_user, l2tp_pass
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

    wa.send(nomor_wa,
        f"Halo {nama}! 🎉\n\n"
        f"Akun VPN Remote MikroTik Anda telah aktif!\n\n"
        f"📦 Paket: {paket}\n"
        f"🔧 Protokol: {script_label}\n"
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
    return templates.TemplateResponse(request=request, name="config.html", context={
        "p": p, "script": script,
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
    return templates.TemplateResponse(request=request, name="detail_pelanggan.html", context={
        "p": p, "vpn_connections": vpn_connections, "vpn_limit": vpn_limit,
        "riwayat": riwayat, "bulan": bulan, "tagihan": tagihan,
        "paket_list": PAKET_LIST,
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
