import base64
import hashlib
import ipaddress
import os
import re
import signal
import socket
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional

from ipwhois import IPWhois
from psycopg import connect
from psycopg.errors import Error as PsycopgError
from scapy.all import IP, IPv6, Raw, TCP, UDP, get_if_list, sniff


INTERFACE = os.getenv("INTERFACE", "auto")
BPF_FILTER = os.getenv("BPF_FILTER", "")
ENABLE_RDNS = os.getenv("ENABLE_RDNS", "false").lower() == "true"
ENABLE_RDAP = os.getenv("ENABLE_RDAP", "true").lower() == "true"
PAYLOAD_MAX_BYTES = int(os.getenv("PAYLOAD_MAX_BYTES", "1024"))
FLUSH_INTERVAL = int(os.getenv("FLUSH_INTERVAL", "1"))
POSTGRES_DSN = os.getenv("POSTGRES_DSN", "")
POSTGRES_TABLE = os.getenv("POSTGRES_TABLE", "threat_intel_events")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "")
POSTGRES_USER = os.getenv("POSTGRES_USER", "postgres")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "")
SOURCE_NAME = os.getenv("SOURCE_NAME", "default")

URL_RE = re.compile(rb"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(rb"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24}\b")
CVE_RE = re.compile(rb"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
HASH_MD5_RE = re.compile(rb"\b[a-fA-F0-9]{32}\b")
HASH_SHA1_RE = re.compile(rb"\b[a-fA-F0-9]{40}\b")
HASH_SHA256_RE = re.compile(rb"\b[a-fA-F0-9]{64}\b")

COMMON_ATTACK_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "submission",
    631: "ipp",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

FIELDNAMES = [
    "timestamp_utc",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "transport",
    "ip_proto",
    "packet_len",
    "ttl_hoplimit",
    "tcp_flags",
    "service_guess",
    "is_scan_like",
    "ioc_ips",
    "ioc_domains",
    "ioc_urls",
    "ioc_hashes",
    "ioc_cves",
    "payload_sha256",
    "payload_b64",
    "rdns",
    "is_private",
    "is_reserved",
    "is_multicast",
    "country",
    "asn",
    "asn_description",
    "whois_network",
]


@dataclass
class IntelRecord:
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str
    transport: str
    ip_proto: str
    packet_len: int
    ttl_hoplimit: str
    tcp_flags: str
    payload: bytes


class IntelCollector:
    def __init__(self):
        self.lock = threading.Lock()
        self.packet_counter = 0

        self.rdns_cache: Dict[str, str] = {}
        self.rdap_cache: Dict[str, Dict[str, str]] = {}
        self.pg_conn = None
        self.pg_cursor = None

        if self._effective_postgres_dsn():
            self._init_postgres()

    def _effective_postgres_dsn(self) -> str:
        if POSTGRES_DSN:
            return POSTGRES_DSN
        if POSTGRES_HOST and POSTGRES_DB and POSTGRES_PASSWORD:
            return (
                f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
                f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
            )
        return ""

    def _init_postgres(self):
        try:
            dsn = self._effective_postgres_dsn()
            self.pg_conn = connect(dsn)
            self.pg_conn.autocommit = True
            self.pg_cursor = self.pg_conn.cursor()
            self.pg_cursor.execute("SELECT current_database(), current_user, 1")
            db_name, db_user, probe = self.pg_cursor.fetchone()
            if probe == 1:
                print(
                    f"[*] PostgreSQL self-test OK: db='{db_name}' user='{db_user}'",
                    flush=True,
                )
            self.pg_cursor.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {POSTGRES_TABLE} (
                    id BIGSERIAL PRIMARY KEY,
                    source_name TEXT,
                    timestamp_utc TIMESTAMPTZ,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port TEXT,
                    dst_port TEXT,
                    transport TEXT,
                    ip_proto TEXT,
                    packet_len INTEGER,
                    ttl_hoplimit TEXT,
                    tcp_flags TEXT,
                    service_guess TEXT,
                    is_scan_like BOOLEAN,
                    ioc_ips TEXT,
                    ioc_domains TEXT,
                    ioc_urls TEXT,
                    ioc_hashes TEXT,
                    ioc_cves TEXT,
                    payload_sha256 TEXT,
                    payload_b64 TEXT,
                    rdns TEXT,
                    is_private BOOLEAN,
                    is_reserved BOOLEAN,
                    is_multicast BOOLEAN,
                    country TEXT,
                    asn TEXT,
                    asn_description TEXT,
                    whois_network TEXT
                )
                """
            )
            self.pg_cursor.execute(
                f"ALTER TABLE {POSTGRES_TABLE} ADD COLUMN IF NOT EXISTS source_name TEXT"
            )
            print(
                f"[*] PostgreSQL enabled, writing to table '{POSTGRES_TABLE}'",
                flush=True,
            )
        except Exception as exc:
            print(f"[!] PostgreSQL self-test FAILED: {exc}", flush=True)
            self.pg_cursor = None
            self.pg_conn = None

    def close(self):
        if self.pg_cursor is not None:
            self.pg_cursor.close()
        if self.pg_conn is not None:
            self.pg_conn.close()

    def _safe_bool(self, value: str) -> bool:
        return str(value).lower() == "true"

    def _is_local_ip(self, ip_str: str) -> bool:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        )

    def _write_postgres(self, row: Dict[str, str]):
        if self.pg_cursor is None:
            return

        try:
            self.pg_cursor.execute(
                f"""
                INSERT INTO {POSTGRES_TABLE} (
                    source_name, timestamp_utc, src_ip, dst_ip, src_port, dst_port, transport,
                    ip_proto, packet_len, ttl_hoplimit, tcp_flags, service_guess,
                    is_scan_like, ioc_ips, ioc_domains, ioc_urls, ioc_hashes,
                    ioc_cves, payload_sha256, payload_b64, rdns, is_private,
                    is_reserved, is_multicast, country, asn, asn_description,
                    whois_network
                ) VALUES (
                    %(source_name)s, %(timestamp_utc)s, %(src_ip)s, %(dst_ip)s, %(src_port)s,
                    %(dst_port)s, %(transport)s, %(ip_proto)s, %(packet_len)s,
                    %(ttl_hoplimit)s, %(tcp_flags)s, %(service_guess)s,
                    %(is_scan_like_bool)s, %(ioc_ips)s, %(ioc_domains)s,
                    %(ioc_urls)s, %(ioc_hashes)s, %(ioc_cves)s,
                    %(payload_sha256)s, %(payload_b64)s, %(rdns)s,
                    %(is_private_bool)s, %(is_reserved_bool)s,
                    %(is_multicast_bool)s, %(country)s, %(asn)s,
                    %(asn_description)s, %(whois_network)s
                )
                """,
                {
                    **row,
                    "is_scan_like_bool": self._safe_bool(row["is_scan_like"]),
                    "is_private_bool": self._safe_bool(row["is_private"]),
                    "is_reserved_bool": self._safe_bool(row["is_reserved"]),
                    "is_multicast_bool": self._safe_bool(row["is_multicast"]),
                },
            )
        except PsycopgError as exc:
            print(f"[!] PostgreSQL insert failed: {exc}", flush=True)

    def _extract_iocs(self, payload: bytes):
        urls = sorted({m.decode("utf-8", errors="ignore") for m in URL_RE.findall(payload)})
        ips = sorted({m.decode("utf-8", errors="ignore") for m in IP_RE.findall(payload)})
        domains = sorted({m.decode("utf-8", errors="ignore") for m in DOMAIN_RE.findall(payload)})
        cves = sorted({m.decode("utf-8", errors="ignore").upper() for m in CVE_RE.findall(payload)})

        hashes = set()
        for regex in (HASH_MD5_RE, HASH_SHA1_RE, HASH_SHA256_RE):
            hashes.update(m.decode("utf-8", errors="ignore") for m in regex.findall(payload))

        return {
            "ioc_urls": "|".join(urls),
            "ioc_ips": "|".join(ips),
            "ioc_domains": "|".join(domains),
            "ioc_cves": "|".join(cves),
            "ioc_hashes": "|".join(sorted(hashes)),
        }

    def _safe_rdns(self, ip_str: str) -> str:
        if not ENABLE_RDNS:
            return ""

        cached = self.rdns_cache.get(ip_str)
        if cached is not None:
            return cached

        result = ""
        try:
            result = socket.gethostbyaddr(ip_str)[0]
        except Exception:
            result = ""

        self.rdns_cache[ip_str] = result
        return result

    def _safe_rdap(self, ip_str: str) -> Dict[str, str]:
        empty = {
            "country": "",
            "asn": "",
            "asn_description": "",
            "whois_network": "",
        }

        if not ENABLE_RDAP:
            return empty

        cached = self.rdap_cache.get(ip_str)
        if cached is not None:
            return cached

        try:
            data = IPWhois(ip_str).lookup_rdap(depth=1)
            network = data.get("network") or {}
            parsed = {
                "country": str(network.get("country") or ""),
                "asn": str(data.get("asn") or ""),
                "asn_description": str(data.get("asn_description") or ""),
                "whois_network": str(network.get("name") or ""),
            }
            self.rdap_cache[ip_str] = parsed
            return parsed
        except Exception:
            self.rdap_cache[ip_str] = empty
            return empty

    def _service_guess(self, dst_port: str) -> str:
        if not dst_port:
            return ""
        try:
            return COMMON_ATTACK_PORTS.get(int(dst_port), "")
        except ValueError:
            return ""

    def _is_scan_like(self, transport: str, tcp_flags: str, payload_len: int) -> str:
        # SYN-only packets with empty payload are often scan traffic.
        if transport == "TCP" and tcp_flags == "S" and payload_len == 0:
            return "true"
        if transport == "UDP" and payload_len == 0:
            return "true"
        return "false"

    def write_record(self, rec: IntelRecord):
        if self._is_local_ip(rec.src_ip) or self._is_local_ip(rec.dst_ip):
            return

        src_ip_obj = ipaddress.ip_address(rec.src_ip)
        ioc_info = self._extract_iocs(rec.payload)
        rdns = self._safe_rdns(rec.src_ip)
        rdap = self._safe_rdap(rec.src_ip) if src_ip_obj.is_global else {
            "country": "",
            "asn": "",
            "asn_description": "",
            "whois_network": "",
        }

        row = {
            "source_name": SOURCE_NAME,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "src_ip": rec.src_ip,
            "dst_ip": rec.dst_ip,
            "src_port": rec.src_port,
            "dst_port": rec.dst_port,
            "transport": rec.transport,
            "ip_proto": rec.ip_proto,
            "packet_len": rec.packet_len,
            "ttl_hoplimit": rec.ttl_hoplimit,
            "tcp_flags": rec.tcp_flags,
            "service_guess": self._service_guess(rec.dst_port),
            "is_scan_like": self._is_scan_like(rec.transport, rec.tcp_flags, len(rec.payload)),
            "payload_sha256": hashlib.sha256(rec.payload).hexdigest() if rec.payload else "",
            "payload_b64": base64.b64encode(rec.payload).decode("ascii") if rec.payload else "",
            "rdns": rdns,
            "is_private": str(src_ip_obj.is_private).lower(),
            "is_reserved": str(src_ip_obj.is_reserved).lower(),
            "is_multicast": str(src_ip_obj.is_multicast).lower(),
            "country": rdap["country"],
            "asn": rdap["asn"],
            "asn_description": rdap["asn_description"],
            "whois_network": rdap["whois_network"],
        }
        row.update(ioc_info)

        with self.lock:
            self._write_postgres(row)
            self.packet_counter += 1


def packet_to_record(pkt) -> Optional[IntelRecord]:
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = str(ip_layer.proto)
        ttl_hoplimit = str(ip_layer.ttl)
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = str(ip_layer.nh)
        ttl_hoplimit = str(ip_layer.hlim)
    else:
        return None

    src_port = ""
    dst_port = ""
    tcp_flags = ""

    if TCP in pkt:
        transport = "TCP"
        tcp_layer = pkt[TCP]
        src_port = str(tcp_layer.sport)
        dst_port = str(tcp_layer.dport)
        tcp_flags = str(tcp_layer.flags)
    elif UDP in pkt:
        transport = "UDP"
        udp_layer = pkt[UDP]
        src_port = str(udp_layer.sport)
        dst_port = str(udp_layer.dport)
    else:
        transport = "OTHER"

    payload = b""
    if Raw in pkt:
        payload = bytes(pkt[Raw].load[:PAYLOAD_MAX_BYTES])

    return IntelRecord(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        transport=transport,
        ip_proto=proto,
        packet_len=len(bytes(pkt)),
        ttl_hoplimit=ttl_hoplimit,
        tcp_flags=tcp_flags,
        payload=payload,
    )


def main():
    collector = IntelCollector()
    stopped = threading.Event()

    available_interfaces = get_if_list()

    def choose_interface(requested: str) -> str:
        if requested != "auto" and requested in available_interfaces:
            return requested
        if requested == "auto" and "any" in available_interfaces:
            return "any"

        for iface in available_interfaces:
            lowered = iface.lower()
            if "lo" not in lowered and "loopback" not in lowered:
                return iface

        if available_interfaces:
            return available_interfaces[0]

        raise RuntimeError("No sniffable network interfaces found")

    selected_interface = choose_interface(INTERFACE)

    def handle_signal(signum, frame):
        _ = (signum, frame)
        stopped.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    def process_packet(pkt):
        if stopped.is_set():
            return
        rec = packet_to_record(pkt)
        if rec is not None:
            collector.write_record(rec)

    print(
        f"[*] Starting capture on interface='{selected_interface}' filter='{BPF_FILTER or 'none'}'",
        flush=True,
    )
    print("[*] CSV output disabled; streaming events to PostgreSQL only", flush=True)

    try:
        sniff(
            iface=selected_interface,
            filter=BPF_FILTER or None,
            prn=process_packet,
            store=False,
            stop_filter=lambda _: stopped.is_set(),
        )
    except PermissionError:
        print("[!] Permission denied. Run container with NET_RAW/NET_ADMIN or privileged mode.", flush=True)
        collector.close()
        sys.exit(1)
    except Exception as exc:
        print(f"[!] Capture error: {exc}", flush=True)
        collector.close()
        sys.exit(1)

    collector.close()
    print("[*] Stopped capture cleanly", flush=True)


if __name__ == "__main__":
    main()
