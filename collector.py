import base64
import hashlib
import ipaddress
import math
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
EXEMPT_IPS_FILE = os.getenv("EXEMPT_IPS_FILE", "/app/exempt_ips.txt")

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
    # Additional attack-relevant ports
    88: "kerberos",
    102: "s7comm",
    502: "modbus",
    636: "ldaps",
    1883: "mqtt",
    2181: "zookeeper",
    2222: "ssh-alt",
    3268: "ldap-gc",
    3269: "ldaps-gc",
    3690: "svn",
    4369: "epmd",
    4444: "meterpreter",
    4505: "saltstack",
    4506: "saltstack-ret",
    4848: "glassfish",
    5000: "docker-registry",
    5984: "couchdb",
    5985: "winrm",
    5986: "winrm-https",
    6000: "x11",
    6443: "kubernetes-api",
    6667: "irc",
    7001: "weblogic",
    7077: "spark-master",
    7474: "neo4j",
    8001: "kubernetes-proxy",
    8009: "ajp13",
    8083: "influxdb",
    8086: "influxdb-api",
    8088: "yarn-ui",
    8140: "puppet",
    8161: "activemq",
    8888: "jupyter",
    8883: "mqtt-ssl",
    9000: "php-fpm",
    9042: "cassandra",
    9083: "hive-metastore",
    9090: "prometheus",
    9092: "kafka",
    9300: "elasticsearch-transport",
    10000: "hiveserver2",
    10250: "kubelet",
    10255: "kubelet-readonly",
    15672: "rabbitmq-mgmt",
    20000: "dnp3",
    44818: "ethernetip",
    50070: "hdfs-namenode",
}

# Application-layer banner signatures for service identification
BANNER_SIGNATURES: list[tuple[str, re.Pattern]] = [
    # ── Secure Shell ───────────────────────────────────────────────────────
    ("ssh",           re.compile(rb"^SSH-\d+\.\d+-", re.MULTILINE)),
    # ── HTTP / HTTP2 ───────────────────────────────────────────────────────
    ("http",          re.compile(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+\S+\s+HTTP/", re.MULTILINE)),
    ("http",          re.compile(rb"^HTTP/[12]\.", re.MULTILINE)),
    ("http2",         re.compile(rb"^PRI \* HTTP/2\.0\r\n\r\nSM\r\n\r\n")),
    ("websocket",     re.compile(rb"Upgrade:\s*websocket", re.IGNORECASE)),
    # ── Mail protocols ─────────────────────────────────────────────────────
    ("ftp",           re.compile(rb"^220[\s-].*ftp", re.MULTILINE | re.IGNORECASE)),
    ("smtp",          re.compile(rb"^220[\s-].*smtp|^EHLO\b|^HELO\b|^MAIL FROM:", re.MULTILINE | re.IGNORECASE)),
    ("pop3",          re.compile(rb"^\+OK\s", re.MULTILINE)),
    ("imap",          re.compile(rb"^\*\s+OK\s", re.MULTILINE)),
    ("nntp",          re.compile(rb"^20[01]\s", re.MULTILINE)),
    # ── Remote desktop / VNC ───────────────────────────────────────────────
    ("rdp",           re.compile(rb"^\x03\x00\x00")),
    ("vnc",           re.compile(rb"^RFB \d{3}\.\d{3}\r\n")),
    # ── Key-value / caching stores ─────────────────────────────────────────
    ("redis",         re.compile(rb"^\*\d+\r\n\$\d+\r\n", re.MULTILINE)),
    ("memcached",     re.compile(rb"^(get|set|delete|stats|version|flush_all)\s", re.MULTILINE)),
    # ── Relational databases ───────────────────────────────────────────────
    ("mysql",         re.compile(rb"[\x00-\xff]{3}\x00\x0a[0-9]+\.")),
    ("postgres",      re.compile(rb"^\x00\x00\x00[\x08-\xff]\x00\x03\x00\x00")),   # startup packet proto 3.0
    ("postgres",      re.compile(rb"^\x00\x00\x00\x08\x04\xd2\x16/")),              # SSL request magic
    ("mssql",         re.compile(rb"^\x12\x01\x00[\x00-\xff]{2}\x00\x00\x00")),    # TDS pre-login
    ("oracle-tns",    re.compile(rb"^\x00[\x00-\xff]\x00\x00\x01\x00\x00\x00")),   # TNS connect
    # ── NoSQL / big-data stores ────────────────────────────────────────────
    ("mongodb",       re.compile(rb"\xd4\x07\x00\x00|\xdc\x07\x00\x00")),
    ("cassandra-cql", re.compile(rb"^\x04[\x00-\xff]\x00\x00\x05")),               # CQL native OPTIONS
    ("zookeeper",     re.compile(rb"^(ruok|stat|mntr|dump|envi|conf|cons|wchs|wchp|wchc|dirs|isro)\n", re.MULTILINE)),
    # ── Messaging / streaming ──────────────────────────────────────────────
    ("amqp",          re.compile(rb"^AMQP\x00[\x00-\x02]")),
    ("mqtt",          re.compile(rb"^\x10[\x00-\xff]{1,4}MQTT")),                  # CONNECT packet type 0x10 + protocol name
    ("stomp",         re.compile(rb"^(CONNECT|STOMP)\n", re.MULTILINE)),
    ("kafka",         re.compile(rb"^\x00\x00\x00[\x00-\xff]\x00[\x00-\x3f]\x00\x00")), # Kafka request header
    # ── Directory / auth ───────────────────────────────────────────────────
    ("smb",           re.compile(rb"\xffSMB|\xfeSMB")),
    ("ldap",          re.compile(rb"^\x30[\x00-\xff]{1,3}\x02[\x01-\x04][\x00-\xff]\x60")),
    ("kerberos",      re.compile(rb"^\x6a[\x00-\xff]{1,4}\x30")),                  # AS-REQ / KRB_AS_REQ
    # ── Network infrastructure ─────────────────────────────────────────────
    ("dns",           re.compile(rb"[\x00-\xff]{2}[\x81\x84][\x00\x80]")),
    ("ntp",           re.compile(rb"^\x1b[\x00-\xff]{3}")),                        # NTP client request (LI=0, VN=3, mode=3)
    ("bgp",           re.compile(rb"^\xff{16}")),                                  # BGP marker
    ("snmp",          re.compile(rb"^\x30[\x00-\xff]{1,3}\x02\x01[\x00-\x03]\x04")), # SNMP community BER
    ("tftp",          re.compile(rb"^\x00[\x01\x02]")),                            # TFTP RRQ/WRQ
    ("nfs-rpc",       re.compile(rb"[\x00-\xff]{4}\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa3")), # RPC CALL to NFS program
    # ── Proxies / tunnels ──────────────────────────────────────────────────
    ("telnet",        re.compile(rb"\xff[\xfb-\xfe].")),
    ("socks4",        re.compile(rb"^\x04[\x01\x02]")),
    ("socks5",        re.compile(rb"^\x05[\x01-\x09]")),
    ("openvpn",       re.compile(rb"^\x00[\x00-\xff]\x38")),                       # OpenVPN control channel
    ("wireguard",     re.compile(rb"^\x01\x00\x00\x00")),                          # WireGuard handshake initiation type=1
    # ── Real-time / media ──────────────────────────────────────────────────
    ("sip",           re.compile(rb"^(INVITE|REGISTER|OPTIONS|BYE|CANCEL|ACK|PRACK|SUBSCRIBE|NOTIFY|PUBLISH|REFER|MESSAGE|UPDATE)\s+sip", re.MULTILINE | re.IGNORECASE)),
    ("sip-response",  re.compile(rb"^SIP/2\.0\s+\d{3}", re.MULTILINE)),
    ("rtsp",          re.compile(rb"^(DESCRIBE|ANNOUNCE|SETUP|PLAY|PAUSE|RECORD|TEARDOWN|OPTIONS)\s+rtsp://", re.MULTILINE | re.IGNORECASE)),
    ("rtmp",          re.compile(rb"^\x03[\x00]{3}")),                             # RTMP handshake C0+C1
    # ── Dev / ops tooling ──────────────────────────────────────────────────
    ("rsync",         re.compile(rb"^@RSYNCD:")),
    ("git",           re.compile(rb"^(git-upload-pack|git-receive-pack|git-upload-archive)\s", re.MULTILINE)),
    ("x11",           re.compile(rb"^[lB]\x00[\x0b\x00]{2}")),                    # X11 connection request byte-order flag
    ("irc",           re.compile(rb"^(NICK|USER|JOIN|PRIVMSG|PASS|CAP)\s", re.MULTILINE)),
]

# Known attack payload signatures — returns tag labels written to attack_tags column
ATTACK_SIGNATURES: list[tuple[str, re.Pattern]] = [
    # SQL injection
    ("sqli",         re.compile(
        rb"union\s+(all\s+)?select\b|'\s*(or|and)\s+'?\d'?\s*=\s*'?\d"
        rb"|sleep\s*\(\s*\d|benchmark\s*\(|waitfor\s+delay|xp_cmdshell"
        rb"|load_file\s*\(|into\s+outfile\b",
        re.IGNORECASE,
    )),
    # Cross-site scripting
    ("xss",          re.compile(
        rb"<script[\s>]|javascript\s*:|on(error|load|click|mouseover)\s*=|<iframe[\s>]|alert\s*\(",
        re.IGNORECASE,
    )),
    # OS command injection
    ("cmdinject",    re.compile(
        rb";\s*(id|whoami|uname|ls|cat)\b|[|&]\s*/bin/(sh|bash|dash|nc)\b|\$\([^)]{2,}\)|`[^`]{3,}`",
        re.IGNORECASE,
    )),
    # Directory / path traversal
    ("traversal",    re.compile(
        rb"\.\./\.\./|\.\.[/\\](\.\.[/\\])+|%2e%2e%2f|%252e%252e%252f",
        re.IGNORECASE,
    )),
    # SSRF targets
    ("ssrf",         re.compile(
        rb"169\.254\.169\.254|metadata\.google\.internal|file://|dict://|gopher://",
        re.IGNORECASE,
    )),
    # Log4Shell (CVE-2021-44228)
    ("log4shell",    re.compile(
        rb"\$\{jndi\s*:|j\}n\}d\}i\}:|%24%7bjndi",
        re.IGNORECASE,
    )),
    # Spring4Shell (CVE-2022-22965)
    ("spring4shell", re.compile(
        rb"class\.module\.classLoader|ClassLoader\.resources\.dirContext",
        re.IGNORECASE,
    )),
    # Shellshock (CVE-2014-6271)
    ("shellshock",   re.compile(rb"\(\)\s*\{\s*:;\s*\}", re.IGNORECASE)),
    # PHP webshell / code execution
    ("webshell",     re.compile(
        rb"(system|exec|passthru|shell_exec)\s*\(|eval\s*\(\s*base64_decode\s*\(|cmd\.exe\s*/c",
        re.IGNORECASE,
    )),
    # Mimikatz / credential dumping
    ("mimikatz",     re.compile(
        rb"sekurlsa::|lsadump::|privilege::debug|token::elevate|kerberos::(ptt|golden)",
        re.IGNORECASE,
    )),
    # Scanner / exploitation tool fingerprints
    ("scanner",      re.compile(
        rb"\b(nmap|masscan|zgrab|nuclei|nikto|sqlmap|dirbuster|gobuster|wfuzz|hydra|medusa|metasploit)\b",
        re.IGNORECASE,
    )),
    # XXE injection
    ("xxe",          re.compile(
        rb"<!ENTITY\s+\S+\s+SYSTEM\s+[\"']|<!DOCTYPE\s+\S+\s+\[",
        re.IGNORECASE,
    )),
    # Server-side template injection
    ("ssti",         re.compile(rb"\{\{[^}]+\}\}|\$\{[^}]+\}", re.IGNORECASE)),
    # TLS Heartbeat / Heartbleed (ContentType=0x18)
    ("heartbleed",   re.compile(rb"\x18\x03[\x00-\x03]")),
    # Default / weak credential attempt patterns
    ("weak-creds",   re.compile(
        rb"\b(admin|root|test|guest|oracle|sa):(admin|password|123456|root|toor|pass|test|letmein|changeme)\b",
        re.IGNORECASE,
    )),
    # HTTP CONNECT proxy abuse
    ("proxy-abuse",  re.compile(rb"^CONNECT\s+\S+:\d+\s+HTTP/", re.IGNORECASE | re.MULTILINE)),
    # PHP LFI / RFI
    ("lfi-rfi",      re.compile(
        rb"(include|require)(_once)?\s*\(\s*[\"'](https?://|php://|data:|zip://|phar://)",
        re.IGNORECASE,
    )),
    # DNS zone transfer (AXFR — query type 252 in DNS wire format)
    ("dns-axfr",     re.compile(rb"[\x00-\xff]{2}\x00\xfc")),
    # ICS/SCADA Modbus function codes (read/write coils, holding registers)
    ("modbus",       re.compile(rb"^\x00[\x00-\xff]\x00\x00[\x00-\xff]{2}[\x01-\x10]", re.MULTILINE)),
]

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
    "attack_tags",
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
        self._exempt_networks = self._load_exempt_networks()

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
                    whois_network TEXT,
                    attack_tags TEXT
                )
                """
            )
            self.pg_cursor.execute(
                f"ALTER TABLE {POSTGRES_TABLE} ADD COLUMN IF NOT EXISTS source_name TEXT"
            )
            self.pg_cursor.execute(
                f"ALTER TABLE {POSTGRES_TABLE} ADD COLUMN IF NOT EXISTS attack_tags TEXT"
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

    def _is_encrypted_payload(self, payload: bytes) -> bool:
        if not payload or len(payload) < 8:
            return False
        # TLS/SSL handshake: ContentType=0x16, ProtocolVersion 0x03xx
        if payload[0] == 0x16 and len(payload) > 2 and payload[1] == 0x03:
            return True
        # High Shannon entropy (>= 7.2 bits/byte) indicates encrypted or compressed data
        counts = [0] * 256
        for b in payload:
            counts[b] += 1
        length = len(payload)
        entropy = 0.0
        for c in counts:
            if c:
                p = c / length
                entropy -= p * math.log2(p)
        return entropy >= 7.2

    def _load_exempt_networks(self) -> list:
        networks = []
        if not EXEMPT_IPS_FILE or not os.path.isfile(EXEMPT_IPS_FILE):
            return networks
        with open(EXEMPT_IPS_FILE, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    networks.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    print(f"[!] Skipping invalid exempt entry: {line!r}", flush=True)
        print(f"[*] Loaded {len(networks)} exempt network(s) from {EXEMPT_IPS_FILE}", flush=True)
        return networks

    def _is_exempt(self, ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(ip_obj in net for net in self._exempt_networks)

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
                    whois_network, attack_tags
                ) VALUES (
                    %(source_name)s, %(timestamp_utc)s, %(src_ip)s, %(dst_ip)s, %(src_port)s,
                    %(dst_port)s, %(transport)s, %(ip_proto)s, %(packet_len)s,
                    %(ttl_hoplimit)s, %(tcp_flags)s, %(service_guess)s,
                    %(is_scan_like_bool)s, %(ioc_ips)s, %(ioc_domains)s,
                    %(ioc_urls)s, %(ioc_hashes)s, %(ioc_cves)s,
                    %(payload_sha256)s, %(payload_b64)s, %(rdns)s,
                    %(is_private_bool)s, %(is_reserved_bool)s,
                    %(is_multicast_bool)s, %(country)s, %(asn)s,
                    %(asn_description)s, %(whois_network)s, %(attack_tags)s
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

    def _service_guess(self, dst_port: str, src_port: str = "", payload: bytes = b"") -> str:
        # 1. Application-layer banner/signature takes highest priority
        if payload:
            for svc, pat in BANNER_SIGNATURES:
                if pat.search(payload):
                    return svc
        # 2. Fall back to well-known port lookup (dst first, then src)
        for port_str in (dst_port, src_port):
            if port_str:
                try:
                    svc = COMMON_ATTACK_PORTS.get(int(port_str))
                    if svc:
                        return svc
                except ValueError:
                    pass
        return ""

    def _detect_attack_type(self, payload: bytes) -> str:
        """Return pipe-delimited set of matched attack tags, or empty string."""
        if not payload:
            return ""
        tags = []
        for label, pat in ATTACK_SIGNATURES:
            if pat.search(payload):
                if label not in tags:
                    tags.append(label)
        return "|".join(tags)

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
        if self._is_exempt(rec.src_ip) or self._is_exempt(rec.dst_ip):
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
            "service_guess": self._service_guess(rec.dst_port, rec.src_port, rec.payload),
            "is_scan_like": self._is_scan_like(rec.transport, rec.tcp_flags, len(rec.payload)),
            "payload_sha256": hashlib.sha256(rec.payload).hexdigest() if rec.payload else "",
            "payload_b64": "encrypted" if self._is_encrypted_payload(rec.payload) else (base64.b64encode(rec.payload).decode("ascii") if rec.payload else ""),
            "rdns": rdns,
            "is_private": str(src_ip_obj.is_private).lower(),
            "is_reserved": str(src_ip_obj.is_reserved).lower(),
            "is_multicast": str(src_ip_obj.is_multicast).lower(),
            "country": rdap["country"],
            "asn": rdap["asn"],
            "asn_description": rdap["asn_description"],
            "whois_network": rdap["whois_network"],
            "attack_tags": self._detect_attack_type(rec.payload),
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
