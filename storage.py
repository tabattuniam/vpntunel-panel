"""Storage — SQLite untuk panel vpntunel."""
from __future__ import annotations
import json
import sqlite3
import time
import uuid
from pathlib import Path


class Storage:
    def __init__(self, db_path: str):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._init()

    def _conn(self):
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def _init(self):
        con = self._conn()
        con.executescript("""
        CREATE TABLE IF NOT EXISTS servers (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            kode            TEXT NOT NULL UNIQUE,
            nama            TEXT NOT NULL,
            ip              TEXT NOT NULL,
            frp_port        INTEGER DEFAULT 7000,
            subdomain_host  TEXT NOT NULL,
            port_start      INTEGER DEFAULT 10000,
            port_end        INTEGER DEFAULT 20000,
            status          TEXT DEFAULT 'aktif'
        );
        CREATE TABLE IF NOT EXISTS pelanggan (
            id              TEXT PRIMARY KEY,
            nama            TEXT NOT NULL,
            nomor_wa        TEXT NOT NULL,
            subdomain       TEXT NOT NULL UNIQUE,
            ports           TEXT NOT NULL DEFAULT '[]',
            paket           TEXT NOT NULL,
            harga           INTEGER NOT NULL,
            tanggal_bayar   INTEGER NOT NULL,
            tanggal_mulai   TEXT NOT NULL,
            status          TEXT DEFAULT 'aktif',
            catatan         TEXT DEFAULT '',
            pin             TEXT DEFAULT '',
            protocol        TEXT DEFAULT 'wireguard',
            wg_private_key  TEXT DEFAULT '',
            wg_public_key   TEXT DEFAULT '',
            vpn_ip          TEXT DEFAULT '',
            l2tp_user       TEXT DEFAULT '',
            l2tp_password   TEXT DEFAULT '',
            server_id       INTEGER DEFAULT 1,
            created_at      INTEGER,
            updated_at      INTEGER
        );
        CREATE TABLE IF NOT EXISTS port_usage (
            port        INTEGER PRIMARY KEY,
            pelanggan_id TEXT NOT NULL,
            label       TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS pembayaran (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            pelanggan_id    TEXT NOT NULL,
            bulan           TEXT NOT NULL,
            lunas           INTEGER DEFAULT 0,
            tanggal_lunas   TEXT,
            created_at      INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_bayar ON pembayaran(pelanggan_id, bulan);
        CREATE TABLE IF NOT EXISTS orders (
            id              TEXT PRIMARY KEY,
            pelanggan_id    TEXT NOT NULL,
            type            TEXT NOT NULL,
            amount          INTEGER NOT NULL,
            metadata        TEXT DEFAULT '{}',
            status          TEXT DEFAULT 'pending',
            snap_token      TEXT DEFAULT '',
            snap_url        TEXT DEFAULT '',
            created_at      INTEGER,
            updated_at      INTEGER
        );
        CREATE TABLE IF NOT EXISTS vpn_connections (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            pelanggan_id    TEXT NOT NULL,
            label           TEXT DEFAULT '',
            protocol        TEXT DEFAULT 'wireguard',
            wg_private_key  TEXT DEFAULT '',
            wg_public_key   TEXT DEFAULT '',
            vpn_ip          TEXT DEFAULT '',
            l2tp_user       TEXT DEFAULT '',
            l2tp_password   TEXT DEFAULT '',
            status          TEXT DEFAULT 'aktif',
            created_at      INTEGER
        );
        """)
        con.commit()
        self._migrate_columns(con)
        # Migrate existing VPN data from pelanggan table to vpn_connections
        self._migrate_vpn_connections(con)
        con.close()

    def _migrate_columns(self, con):
        """Add new columns to existing tables if missing."""
        for stmt in [
            "ALTER TABLE pelanggan ADD COLUMN vpn_limit INTEGER DEFAULT 0",
            "ALTER TABLE pelanggan ADD COLUMN server_id INTEGER DEFAULT 1",
        ]:
            try:
                con.execute(stmt)
                con.commit()
            except Exception:
                pass

    def _migrate_vpn_connections(self, con):
        """Move VPN data already in pelanggan rows into vpn_connections (once)."""
        rows = con.execute(
            "SELECT id, subdomain, protocol, wg_private_key, wg_public_key, vpn_ip, l2tp_user, l2tp_password "
            "FROM pelanggan WHERE (vpn_ip != '' OR l2tp_user != '')"
        ).fetchall()
        for r in rows:
            exists = con.execute(
                "SELECT id FROM vpn_connections WHERE pelanggan_id=?", (r["id"],)
            ).fetchone()
            if exists:
                continue
            label = "VPN 1"
            con.execute(
                "INSERT INTO vpn_connections (pelanggan_id, label, protocol, wg_private_key, wg_public_key, vpn_ip, l2tp_user, l2tp_password, status, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (r["id"], label, r["protocol"], r["wg_private_key"], r["wg_public_key"],
                 r["vpn_ip"], r["l2tp_user"], r["l2tp_password"], "aktif", int(time.time()))
            )
        con.commit()

    def get_used_ports(self) -> set[int]:
        con = self._conn()
        rows = con.execute("SELECT port FROM port_usage").fetchall()
        con.close()
        return {r["port"] for r in rows}

    def get_next_ports(self, server_id: int, count: int) -> list[int]:
        """Ambil 'count' port berikutnya yang tersedia di range server."""
        server = self.get_server(server_id)
        if not server:
            raise ValueError("Server tidak ditemukan")
        used = self.get_used_ports()
        result = []
        for port in range(server["port_start"], server["port_end"] + 1):
            if port not in used:
                result.append(port)
                used.add(port)
                if len(result) == count:
                    return result
        raise ValueError(f"Port range penuh ({server['port_start']}-{server['port_end']})")

    def assign_ports(self, pelanggan_id: str, ports: list[int], labels: list[str] = None):
        con = self._conn()
        for i, port in enumerate(ports):
            label = labels[i] if labels and i < len(labels) else ""
            con.execute("INSERT OR IGNORE INTO port_usage (port, pelanggan_id, label) VALUES (?,?,?)",
                        (port, pelanggan_id, label))
        con.commit()
        con.close()

    def release_ports(self, pelanggan_id: str):
        con = self._conn()
        con.execute("DELETE FROM port_usage WHERE pelanggan_id=?", (pelanggan_id,))
        con.commit()
        con.close()

    def create(self, nama, nomor_wa, subdomain, ports, paket, harga,
               tanggal_bayar, tanggal_mulai, catatan="", pin="",
               protocol="wireguard",
               wg_private_key="", wg_public_key="", vpn_ip="",
               l2tp_user="", l2tp_password="", server_id: int = 1) -> str:
        pid = uuid.uuid4().hex[:8].upper()
        now = int(time.time())
        con = self._conn()
        con.execute(
            """INSERT INTO pelanggan
               (id,nama,nomor_wa,subdomain,ports,paket,harga,
                tanggal_bayar,tanggal_mulai,catatan,pin,protocol,
                wg_private_key,wg_public_key,vpn_ip,
                l2tp_user,l2tp_password,server_id,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (pid, nama, nomor_wa, subdomain, json.dumps(ports), paket, harga,
             int(tanggal_bayar), tanggal_mulai, catatan, pin, protocol,
             wg_private_key, wg_public_key, vpn_ip,
             l2tp_user, l2tp_password, server_id, now, now)
        )
        con.commit()
        con.close()
        return pid

    def get_used_vpn_ips(self) -> set[str]:
        con = self._conn()
        rows1 = con.execute("SELECT vpn_ip FROM pelanggan WHERE vpn_ip != ''").fetchall()
        rows2 = con.execute("SELECT vpn_ip FROM vpn_connections WHERE vpn_ip != ''").fetchall()
        con.close()
        return {r["vpn_ip"] for r in rows1} | {r["vpn_ip"] for r in rows2}

    def assign_next_vpn_ip(self) -> str:
        used = self.get_used_vpn_ips()
        for i in range(2, 254):
            ip = f"10.8.0.{i}"
            if ip not in used:
                return ip
        raise ValueError("IP range habis")

    # ── VPN Connections ───────────────────────────────────────────────────────

    def create_vpn_connection(self, pelanggan_id: str, label: str, protocol: str,
                               wg_private_key="", wg_public_key="", vpn_ip="",
                               l2tp_user="", l2tp_password="") -> int:
        con = self._conn()
        cur = con.execute(
            "INSERT INTO vpn_connections (pelanggan_id, label, protocol, wg_private_key, wg_public_key, vpn_ip, l2tp_user, l2tp_password, status, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (pelanggan_id, label, protocol, wg_private_key, wg_public_key,
             vpn_ip, l2tp_user, l2tp_password, "aktif", int(time.time()))
        )
        con.commit()
        vid = cur.lastrowid
        con.close()
        return vid

    def get_vpn_connections(self, pelanggan_id: str) -> list[dict]:
        con = self._conn()
        rows = con.execute(
            "SELECT * FROM vpn_connections WHERE pelanggan_id=? ORDER BY id",
            (pelanggan_id,)
        ).fetchall()
        con.close()
        return [dict(r) for r in rows]

    def get_vpn_connection(self, vid: int) -> dict | None:
        con = self._conn()
        row = con.execute("SELECT * FROM vpn_connections WHERE id=?", (vid,)).fetchone()
        con.close()
        return dict(row) if row else None

    def count_vpn_connections(self, pelanggan_id: str) -> int:
        con = self._conn()
        n = con.execute(
            "SELECT COUNT(*) FROM vpn_connections WHERE pelanggan_id=?", (pelanggan_id,)
        ).fetchone()[0]
        con.close()
        return n

    def delete_vpn_connection(self, vid: int):
        con = self._conn()
        con.execute("DELETE FROM vpn_connections WHERE id=?", (vid,))
        con.commit()
        con.close()

    def update_vpn_connection_status(self, vid: int, status: str):
        con = self._conn()
        con.execute("UPDATE vpn_connections SET status=? WHERE id=?", (status, vid))
        con.commit()
        con.close()

    def get_by_wa_and_pin(self, nomor_wa: str, pin: str) -> dict | None:
        # normalize
        n = nomor_wa.strip().replace("-","").replace(" ","")
        if n.startswith("0"):
            n = "62" + n[1:]
        elif n.startswith("+"):
            n = n[1:]
        con = self._conn()
        row = con.execute(
            "SELECT * FROM pelanggan WHERE (nomor_wa=? OR nomor_wa=?) AND pin=? AND status='aktif'",
            (nomor_wa.strip(), n, pin)
        ).fetchone()
        con.close()
        if not row:
            return None
        d = dict(row)
        d["ports"] = json.loads(d["ports"])
        return d

    def get(self, pid: str) -> dict | None:
        con = self._conn()
        row = con.execute("SELECT * FROM pelanggan WHERE id=?", (pid,)).fetchone()
        con.close()
        if not row:
            return None
        d = dict(row)
        d["ports"] = json.loads(d["ports"])
        return d

    def list_all(self, status=None) -> list[dict]:
        con = self._conn()
        if status:
            rows = con.execute("SELECT * FROM pelanggan WHERE status=? ORDER BY nama", (status,)).fetchall()
        else:
            rows = con.execute("SELECT * FROM pelanggan ORDER BY nama").fetchall()
        con.close()
        result = []
        for r in rows:
            d = dict(r)
            d["ports"] = json.loads(d["ports"])
            result.append(d)
        return result

    def update_status(self, pid: str, status: str):
        con = self._conn()
        con.execute("UPDATE pelanggan SET status=?,updated_at=? WHERE id=?",
                    (status, int(time.time()), pid))
        con.commit()
        con.close()

    def get_jatuh_tempo_hari_ini(self, hari: int) -> list[dict]:
        con = self._conn()
        rows = con.execute(
            "SELECT * FROM pelanggan WHERE tanggal_bayar=? AND status='aktif'", (hari,)
        ).fetchall()
        con.close()
        result = []
        for r in rows:
            d = dict(r)
            d["ports"] = json.loads(d["ports"])
            result.append(d)
        return result

    def get_or_create_tagihan(self, pelanggan_id: str, bulan: str) -> dict:
        con = self._conn()
        row = con.execute("SELECT * FROM pembayaran WHERE pelanggan_id=? AND bulan=?",
                          (pelanggan_id, bulan)).fetchone()
        if not row:
            con.execute(
                "INSERT OR IGNORE INTO pembayaran (pelanggan_id,bulan,lunas,created_at) VALUES (?,?,0,?)",
                (pelanggan_id, bulan, int(time.time()))
            )
            con.commit()
            row = con.execute("SELECT * FROM pembayaran WHERE pelanggan_id=? AND bulan=?",
                              (pelanggan_id, bulan)).fetchone()
        con.close()
        return dict(row)

    def tandai_lunas(self, pelanggan_id: str, bulan: str):
        from datetime import date
        con = self._conn()
        con.execute(
            """INSERT INTO pembayaran (pelanggan_id,bulan,lunas,tanggal_lunas,created_at)
               VALUES (?,?,1,?,?)
               ON CONFLICT(pelanggan_id,bulan) DO UPDATE SET lunas=1,tanggal_lunas=excluded.tanggal_lunas""",
            (pelanggan_id, bulan, date.today().isoformat(), int(time.time()))
        )
        con.commit()
        con.close()

    def get_tagihan_bulan(self, bulan: str) -> list[dict]:
        con = self._conn()
        rows = con.execute("""
            SELECT p.*, COALESCE(b.lunas,0) as lunas, b.tanggal_lunas
            FROM pelanggan p
            LEFT JOIN pembayaran b ON b.pelanggan_id=p.id AND b.bulan=?
            WHERE p.status='aktif' ORDER BY p.tanggal_bayar, p.nama
        """, (bulan,)).fetchall()
        con.close()
        result = []
        for r in rows:
            d = dict(r)
            d["ports"] = json.loads(d["ports"])
            result.append(d)
        return result

    def count_stats_full(self, bulan: str) -> dict:
        con = self._conn()
        total     = con.execute("SELECT COUNT(*) FROM pelanggan WHERE status='aktif'").fetchone()[0]
        nonaktif  = con.execute("SELECT COUNT(*) FROM pelanggan WHERE status='nonaktif'").fetchone()[0]
        lunas     = con.execute("SELECT COUNT(*) FROM pembayaran WHERE bulan=? AND lunas=1", (bulan,)).fetchone()[0]
        omzet_row = con.execute("SELECT SUM(p.harga) FROM pelanggan p JOIN pembayaran b ON b.pelanggan_id=p.id WHERE b.bulan=? AND b.lunas=1", (bulan,)).fetchone()[0]
        omzet     = omzet_row or 0
        target    = con.execute("SELECT SUM(harga) FROM pelanggan WHERE status='aktif'").fetchone()[0] or 0
        wg_count  = con.execute("SELECT COUNT(*) FROM pelanggan WHERE protocol='wireguard' AND status='aktif'").fetchone()[0]
        l2tp_count= con.execute("SELECT COUNT(*) FROM pelanggan WHERE protocol='l2tp' AND status='aktif'").fetchone()[0]
        recent    = con.execute("SELECT nama, subdomain, protocol, created_at FROM pelanggan ORDER BY created_at DESC LIMIT 5").fetchall()
        con.close()
        return {
            "total": total, "nonaktif": nonaktif,
            "lunas": lunas, "belum": total - lunas,
            "omzet": omzet, "target": target,
            "wg_count": wg_count, "l2tp_count": l2tp_count,
            "recent": [dict(r) for r in recent],
        }

    def count_stats(self, bulan: str) -> dict:
        con = self._conn()
        total = con.execute("SELECT COUNT(*) FROM pelanggan WHERE status='aktif'").fetchone()[0]
        lunas = con.execute(
            "SELECT COUNT(*) FROM pembayaran WHERE bulan=? AND lunas=1", (bulan,)
        ).fetchone()[0]
        con.close()
        return {"total": total, "lunas": lunas, "belum": total - lunas}

    def get_riwayat_bayar(self, pelanggan_id: str) -> list[dict]:
        con = self._conn()
        rows = con.execute(
            "SELECT * FROM pembayaran WHERE pelanggan_id=? ORDER BY bulan DESC",
            (pelanggan_id,)
        ).fetchall()
        con.close()
        return [dict(r) for r in rows]

    def update_pelanggan(self, pid: str, nama: str, nomor_wa: str,
                         tanggal_bayar: int, catatan: str):
        con = self._conn()
        con.execute(
            "UPDATE pelanggan SET nama=?,nomor_wa=?,tanggal_bayar=?,catatan=?,updated_at=? WHERE id=?",
            (nama, nomor_wa, tanggal_bayar, catatan, int(__import__("time").time()), pid)
        )
        con.commit()
        con.close()

    def update_pin(self, pid: str, pin: str):
        con = self._conn()
        con.execute("UPDATE pelanggan SET pin=?,updated_at=? WHERE id=?",
                    (pin, int(__import__("time").time()), pid))
        con.commit()
        con.close()

    def subdomain_exists(self, subdomain: str) -> bool:
        con = self._conn()
        row = con.execute("SELECT id FROM pelanggan WHERE subdomain=?", (subdomain,)).fetchone()
        con.close()
        return row is not None

    # ── Orders (Midtrans) ────────────────────────────────────────────────────

    def create_order(self, pelanggan_id: str, order_type: str, amount: int,
                     metadata: dict = None) -> str:
        oid = "VPN-" + uuid.uuid4().hex[:12].upper()
        now = int(time.time())
        con = self._conn()
        con.execute(
            "INSERT INTO orders (id,pelanggan_id,type,amount,metadata,status,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (oid, pelanggan_id, order_type, amount,
             json.dumps(metadata or {}), "pending", now, now)
        )
        con.commit()
        con.close()
        return oid

    def update_order_snap(self, order_id: str, snap_token: str, snap_url: str):
        con = self._conn()
        con.execute(
            "UPDATE orders SET snap_token=?,snap_url=?,updated_at=? WHERE id=?",
            (snap_token, snap_url, int(time.time()), order_id)
        )
        con.commit()
        con.close()

    def get_order(self, order_id: str) -> dict | None:
        con = self._conn()
        row = con.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        con.close()
        if not row:
            return None
        d = dict(row)
        d["metadata"] = json.loads(d["metadata"])
        return d

    def update_order_status(self, order_id: str, status: str):
        con = self._conn()
        con.execute(
            "UPDATE orders SET status=?,updated_at=? WHERE id=?",
            (status, int(time.time()), order_id)
        )
        con.commit()
        con.close()

    def get_pending_order(self, pelanggan_id: str, order_type: str, ref: str) -> dict | None:
        """Cari order pending agar tidak duplikat (ref = bulan untuk tagihan)."""
        con = self._conn()
        row = con.execute(
            "SELECT * FROM orders WHERE pelanggan_id=? AND type=? AND status='pending' "
            "AND json_extract(metadata,'$.ref')=? ORDER BY created_at DESC LIMIT 1",
            (pelanggan_id, order_type, ref)
        ).fetchone()
        con.close()
        if not row:
            return None
        d = dict(row)
        d["metadata"] = json.loads(d["metadata"])
        return d

    # ── Servers ───────────────────────────────────────────────────────────────

    def list_servers(self) -> list[dict]:
        con = self._conn()
        rows = con.execute("SELECT * FROM servers ORDER BY id").fetchall()
        con.close()
        return [dict(r) for r in rows]

    def get_server(self, sid: int) -> dict | None:
        con = self._conn()
        row = con.execute("SELECT * FROM servers WHERE id=?", (sid,)).fetchone()
        con.close()
        return dict(row) if row else None

    def get_server_by_kode(self, kode: str) -> dict | None:
        con = self._conn()
        row = con.execute("SELECT * FROM servers WHERE kode=?", (kode,)).fetchone()
        con.close()
        return dict(row) if row else None

    def create_server(self, kode: str, nama: str, ip: str, frp_port: int,
                      subdomain_host: str, port_start: int, port_end: int) -> int:
        con = self._conn()
        cur = con.execute(
            "INSERT INTO servers (kode,nama,ip,frp_port,subdomain_host,port_start,port_end,status) "
            "VALUES (?,?,?,?,?,?,?,'aktif')",
            (kode, nama, ip, frp_port, subdomain_host, port_start, port_end)
        )
        con.commit()
        sid = cur.lastrowid
        con.close()
        return sid

    def delete_server(self, sid: int):
        con = self._conn()
        con.execute("DELETE FROM servers WHERE id=?", (sid,))
        con.commit()
        con.close()

    def count_pelanggan_by_server(self, sid: int) -> int:
        con = self._conn()
        n = con.execute(
            "SELECT COUNT(*) FROM pelanggan WHERE server_id=? AND status='aktif'", (sid,)
        ).fetchone()[0]
        con.close()
        return n

    def get_best_server(self) -> dict | None:
        """Pilih server aktif dengan jumlah pelanggan paling sedikit."""
        servers = [s for s in self.list_servers() if s["status"] == "aktif"]
        if not servers:
            return None
        return min(servers, key=lambda s: self.count_pelanggan_by_server(s["id"]))

    def update_pelanggan_server(self, pid: str, server_id: int):
        con = self._conn()
        con.execute("UPDATE pelanggan SET server_id=?,updated_at=? WHERE id=?",
                    (server_id, int(time.time()), pid))
        con.commit()
        con.close()

    def update_paket(self, pid: str, paket: str, harga: int, vpn_limit: int):
        con = self._conn()
        con.execute(
            "UPDATE pelanggan SET paket=?,harga=?,vpn_limit=?,updated_at=? WHERE id=?",
            (paket, harga, vpn_limit, int(time.time()), pid)
        )
        con.commit()
        con.close()
