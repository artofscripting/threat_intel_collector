import base64
import hashlib
import ipaddress
import json
import math
import os
import random
import re
import signal
import socket
import sys
import threading
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional

from ipwhois import IPWhois
from psycopg import connect
from psycopg.errors import Error as PsycopgError
from scapy.all import IP, IPv6, Raw, TCP, UDP, get_if_list, send, sniff


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
EXEMPT_ASNS_FILE = os.getenv("EXEMPT_ASNS_FILE", "/app/exempt_asn.txt")

URL_RE = re.compile(rb"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(rb"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24}\b")
CVE_RE = re.compile(rb"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
HASH_MD5_RE = re.compile(rb"\b[a-fA-F0-9]{32}\b")
HASH_SHA1_RE = re.compile(rb"\b[a-fA-F0-9]{40}\b")
HASH_SHA256_RE = re.compile(rb"\b[a-fA-F0-9]{64}\b")

# HTTP request/response field extraction
HTTP_REQUEST_RE = re.compile(
    rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+(HTTP/[\d.]+)\r?\n",
    re.MULTILINE | re.IGNORECASE,
)
HTTP_RESPONSE_RE = re.compile(
    rb"^(HTTP/[\d.]+)\s+(\d{3})",
    re.MULTILINE | re.IGNORECASE,
)
HTTP_HOST_RE = re.compile(rb"^Host:\s*(.+?)\r?$", re.MULTILINE | re.IGNORECASE)
HTTP_UA_RE = re.compile(rb"^User-Agent:\s*(.+?)\r?$", re.MULTILINE | re.IGNORECASE)
HTTP_REFERER_RE = re.compile(rb"^Referer:\s*(.+?)\r?$", re.MULTILINE | re.IGNORECASE)
HTTP_CONTENT_TYPE_RE = re.compile(rb"^Content-Type:\s*(.+?)\r?$", re.MULTILINE | re.IGNORECASE)

HTTP_200_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

SERVICE_BANNERS: dict[str, bytes] = {
    "ssh": b"SSH-2.0-OpenSSH_8.9p1 Debian-3\r\n",
    "ssh-alt": b"SSH-2.0-OpenSSH_8.9p1 Debian-3\r\n",
    "ftp": b"220 Service ready\r\n",
    "smtp": b"220 mail.local ESMTP ready\r\n",
    "submission": b"220 mail.local ESMTP ready\r\n",
    "pop3": b"+OK POP3 server ready\r\n",
    "imap": b"* OK IMAP4 ready\r\n",
    "telnet": b"Debian GNU/Linux 12\r\nlogin: ",
    "redis": b"-NOAUTH Authentication required.\r\n",
    "memcached": b"ERROR\r\n",
    "mongodb": b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
}

BANNER_FIRST_SERVICES = {
    "ssh",
    "ssh-alt",
    "ftp",
    "smtp",
    "submission",
    "pop3",
    "imap",
    "telnet",
}

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
    # ── Additional HTTP-over-* application layer ───────────────────────────
    ("grpc",          re.compile(rb"content-type:\s*application/grpc", re.IGNORECASE)),
    ("soap",          re.compile(rb"<(?:soapenv|soap-env|SOAP-ENV|s):Envelope", re.IGNORECASE)),
    ("xmlrpc",        re.compile(rb"<methodCall>|<methodResponse>", re.IGNORECASE)),
    ("graphql",       re.compile(rb"\b(query|mutation|subscription)\s+\w*\s*[\{(]", re.IGNORECASE)),
    ("ssdp",          re.compile(rb"^(M-SEARCH|NOTIFY)\s+\*\s+HTTP", re.MULTILINE)),
    ("wsman",         re.compile(rb"<wsman:|<wsa:Action|<wsmid:", re.IGNORECASE)),
    ("prometheus",    re.compile(rb"^# (HELP|TYPE) \w+", re.MULTILINE)),
    ("docker-api",    re.compile(rb"/(v\d+\.\d+/)?(containers|images|networks|volumes)/\w", re.IGNORECASE)),
    ("kubernetes",    re.compile(rb"/api(?:s)?/[\w.]+/v\d+/(?:pods|nodes|services|deployments)/", re.IGNORECASE)),
    # ── Mail / file transfer extras ────────────────────────────────────────
    ("ftp",           re.compile(rb"^(USER|PASS|STOR|RETR|LIST|PASV|PORT|TYPE|QUIT|CWD|MKD|RMD|PWD|NLST|ABOR)\s", re.MULTILINE | re.IGNORECASE)),
    ("smtp-starttls", re.compile(rb"^STARTTLS\r\n", re.MULTILINE | re.IGNORECASE)),
    # ── Remote access extras ───────────────────────────────────────────────
    ("citrix-ica",    re.compile(rb"\x7f\x7f\x49\x43\x41")),                      # Citrix ICA magic "ICA"
    ("rlogin",        re.compile(rb"^\x00[^\x00]{1,16}\x00[^\x00]{1,16}\x00")),
    # ── Proxy / tunnel extras ─────────────────────────────────────────────
    ("l2tp",          re.compile(rb"^\x13\x00[\x00-\xff]{2}\x00\x00\x00\x00")),   # L2TP control, tunnel=0
    ("pptp",          re.compile(rb"[\x00-\xff]{2}\x00\x00\x1a\x2b\x3c\x4d")),   # PPTP magic cookie
    ("dtls",          re.compile(rb"^\x16\xfe[\xff\xfd\xfc]")),                   # DTLS 1.0/1.2/1.3 handshake
    ("stun",          re.compile(rb"^[\x00\x01][\x00-\x03][\x00-\xff]{2}\x21\x12\xa4\x42")), # STUN magic cookie
    # ── Key-value extras ──────────────────────────────────────────────────
    ("redis",         re.compile(rb"^(\+OK|-ERR|\+PONG|-WRONGTYPE|-NOSCRIPT)", re.MULTILINE)),
    ("memcached-bin", re.compile(rb"^\x80[\x00-\x1a][\x00-\xff]{2}\x00")),        # Memcached binary magic 0x80
    # ── NoSQL / data platform extras ──────────────────────────────────────
    ("elasticsearch", re.compile(rb"\"tagline\"\s*:\s*\"You Know, for Search\"", re.IGNORECASE)),
    ("couchdb",       re.compile(rb"\"couchdb\"\s*:\s*\"Welcome\"", re.IGNORECASE)),
    ("hadoop-ipc",    re.compile(rb"^hrpc\x09\x00")),                             # Hadoop IPC hello
    # ── Messaging extras ──────────────────────────────────────────────────
    ("nats",          re.compile(rb"^INFO \{\"server_id\"", re.MULTILINE)),        # NATS server greeting
    ("zmtp",          re.compile(rb"^\xff[\x00-\xff]{8}\x7f")),                   # ZeroMQ ZMTP 3.0 greeting
    ("activemq",      re.compile(rb"^ActiveMQ")),                                 # ActiveMQ broker banner
    # ── Auth / identity extras ────────────────────────────────────────────
    ("ntlm",          re.compile(rb"NTLMSSP\x00[\x01-\x03]")),                    # NTLM negotiate/challenge/auth
    ("dcerpc",        re.compile(rb"^\x05\x00[\x0b\x00\x02\x0c\x0e\x10]")),      # DCERPC bind/request
    ("radius",        re.compile(rb"^[\x01-\x0d][\x00-\xff]\x00[\x14-\xff]")),   # RADIUS code + min length
    ("diameter",      re.compile(rb"^\x01[\x00-\xff]{3}[\x00\x40\x80\xc0][\x00-\xff]{5}")), # Diameter header
    ("tacacs",        re.compile(rb"^\xc0[\x01\x02][\x01\x02\x03]")),             # TACACS+ version + type
    # ── Network management extras ─────────────────────────────────────────
    ("netflow",       re.compile(rb"^\x00[\x05\x09\x0a][\x00-\xff]{2}")),         # NetFlow v5/v9 / IPFIX
    ("sflow",         re.compile(rb"^\x00\x00\x00\x05[\x00-\xff]{4}\x00\x00\x00")), # sFlow v5
    ("ipmi-rmcp",     re.compile(rb"^\x06\x00\xff\x07")),                         # RMCP / IPMI over UDP
    ("netconf",       re.compile(rb"urn:ietf:params:xml:ns:netconf", re.IGNORECASE)), # NETCONF XML
    ("coap",          re.compile(rb"^[\x40-\x5f][\x01-\x05][\x00-\xff]{2}")),    # CoAP CON/NON request (ver=1, method 1-5)
    # ── ICS / SCADA / OT ─────────────────────────────────────────────────
    ("dnp3",          re.compile(rb"^\x05\x64")),                                  # DNP3 start bytes
    ("s7comm",        re.compile(rb"^\x03\x00[\x00-\xff]{2}[\x00-\xff]{3}\x32")), # S7comm via TPKT + COTP + S7 PDU
    ("bacnet",        re.compile(rb"^\x81[\x00-\x0b][\x00-\xff]{2}")),            # BACnet/IP BVLC header
    ("iec104",        re.compile(rb"^\x68[\x04\x0e\x0f\x14\x15]")),               # IEC 60870-5-104 APCI
    ("fins",          re.compile(rb"^FINS[\x00-\xff]{4}")),                       # Omron FINS/TCP header
    ("ethernetip-cip",re.compile(rb"^\x65\x00[\x00-\xff]{2}\x00\x00\x00\x00")),  # EtherNet/IP ListServices
    ("melsec",        re.compile(rb"^Q\x00[\x00-\xff]{2}\xff\x03\x00")),          # MELSEC-Q series PLC
    # ── Healthcare / specialized verticals ────────────────────────────────
    ("dicom",         re.compile(rb"^\x01\x00\x00\x00[\x00-\xff]{2}\x00\x00")),  # DICOM A-ASSOCIATE-RQ
    ("hl7-mllp",      re.compile(rb"^\x0b[A-Z]{3}\|")),                          # HL7 MLLP VT + segment type
    # ── Peer-to-peer / overlay ────────────────────────────────────────────
    ("bittorrent",    re.compile(rb"^\x13BitTorrent protocol")),
    ("bitcoin",       re.compile(rb"^\xf9\xbe\xb4\xd9")),                         # Bitcoin mainnet magic
    ("gnutella",      re.compile(rb"^GNUTELLA (CONNECT|OK)/", re.MULTILINE)),
    ("xmpp",          re.compile(rb"<stream:stream|xmlns=['\"]jabber", re.IGNORECASE)),
    # ── Serialization / RPC frameworks ───────────────────────────────────
    ("thrift",        re.compile(rb"^\x80\x01[\x00-\x02][\x00-\xff]")),           # Apache Thrift binary protocol
    ("avro",          re.compile(rb"^Obj\x01")),                                  # Apache Avro container magic
    ("erlang-dist",   re.compile(rb"^\x00[\x00-\xff]\x70[\x00-\xff]")),           # Erlang distribution challenge tag
    # ── Storage / iSCSI ───────────────────────────────────────────────────
    ("iscsi",         re.compile(rb"InitiatorName=iqn\.|TargetName=iqn\.", re.IGNORECASE)),
    # ── Printer protocols ─────────────────────────────────────────────────
    ("pjl",           re.compile(rb"^@PJL|\x1b%-12345X", re.MULTILINE | re.IGNORECASE)),
]

# Known attack payload signatures — returns tag labels written to attack_tags column
ATTACK_SIGNATURES: list[tuple[str, re.Pattern]] = [
    # SQLi families
    ("sqli-union", re.compile(
        rb"union\s+(all\s+)?select\b|group\s+by\s+\d+\s+having\s+\d=\d",
        re.IGNORECASE,
    )),
    ("sqli-boolean", re.compile(
        rb"'\s*(or|and)\s+'?\d'?\s*=\s*'?\d|\bor\b\s+1=1\b|\band\b\s+1=1\b",
        re.IGNORECASE,
    )),
    ("sqli-time", re.compile(
        rb"sleep\s*\(\s*\d|benchmark\s*\(|waitfor\s+delay|pg_sleep\s*\(",
        re.IGNORECASE,
    )),
    ("sqli-file-write", re.compile(
        rb"into\s+outfile\b|load_file\s*\(|copy\s*\(\s*select.+to\s+program",
        re.IGNORECASE,
    )),
    # XSS families
    ("xss-script", re.compile(
        rb"<script[\s>]|</script>|<iframe[\s>]",
        re.IGNORECASE,
    )),
    ("xss-event", re.compile(
        rb"on(error|load|click|mouseover|focus|mouseenter|submit)\s*=",
        re.IGNORECASE,
    )),
    ("xss-js-uri", re.compile(
        rb"javascript\s*:|data\s*:\s*text/html|vbscript\s*:",
        re.IGNORECASE,
    )),
    # Command injection split into detailed tags
    ("cmd-separator", re.compile(
        rb"(;|\|\||&&|\|)\s*(id|whoami|uname|ifconfig|ip\s+a|netstat|cat\s+/etc/passwd)\b",
        re.IGNORECASE,
    )),
    ("subst-recon", re.compile(
        rb"(\$\(|`)\s*(id|whoami|uname(\s+-a)?|hostname|cat\s+/etc/(passwd|shadow|hosts)|ls\s+-[la]+|ps\s+(aux|ax|-ef)|netstat|ifconfig|ip\s+a(ddr)?)\b",
        re.IGNORECASE,
    )),
    ("subst-download", re.compile(
        rb"(\$\(|`)\s*(curl|wget|fetch|lwp-download|aria2c)\b[^`$)]*https?://",
        re.IGNORECASE,
    )),
    ("subst-interpreter", re.compile(
        rb"(\$\(|`)\s*(/(?:bin|usr/bin)/)?(?:bash|sh|dash|zsh|python3?|perl|ruby|php)\s+(?:-[ce]\s+)?['\"]",
        re.IGNORECASE,
    )),
    ("cmd-bash-sh", re.compile(
        rb"\b(/bin/)?(bash|sh|dash|zsh)\b\s*(-c\s+)?",
        re.IGNORECASE,
    )),
    ("cmd-powershell", re.compile(
        rb"\bpowershell(\.exe)?\b|\bpwsh\b|-enc(odedcommand)?\b|frombase64string\(",
        re.IGNORECASE,
    )),
    ("cmd-windows", re.compile(
        rb"\bcmd\.exe\s*/c\b|\bwmic\b|\brundll32\b|\bregsvr32\b|\bmshta\b|\bbitsadmin\b",
        re.IGNORECASE,
    )),
    ("cmd-reverse-shell", re.compile(
        rb"bash\s+-i\s+>&\s*/dev/tcp/|nc\s+-e\s+/bin/(sh|bash)|python\s+-c\s+['\"][^'\"]*socket",
        re.IGNORECASE,
    )),
    ("cmd-downloader", re.compile(
        rb"\b(curl|wget|certutil|invoke-webrequest|invoke-expression|iex)\b.+(http|https)://",
        re.IGNORECASE,
    )),
    ("cmd-recon", re.compile(
        rb"\b(id|whoami|uname\s+-a|hostname|cat\s+/etc/(passwd|shadow)|ls\s+-la)\b",
        re.IGNORECASE,
    )),
    # Path traversal and file abuse
    ("traversal", re.compile(
        rb"\.\./\.\./|\.\.[/\\](\.\.[/\\])+|%2e%2e%2f|%252e%252e%252f|%c0%ae%c0%ae",
        re.IGNORECASE,
    )),
    ("lfi", re.compile(
        rb"/(etc/passwd|etc/shadow|proc/self/environ|windows/win\.ini)|php://filter",
        re.IGNORECASE,
    )),
    ("rfi", re.compile(
        rb"(include|require)(_once)?\s*\(\s*[\"']https?://|\bauto_prepend_file\s*=\s*https?://",
        re.IGNORECASE,
    )),
    # SSRF and cloud metadata hits
    ("ssrf", re.compile(
        rb"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|latest/meta-data",
        re.IGNORECASE,
    )),
    ("ssrf-scheme", re.compile(
        rb"file://|dict://|gopher://|ftp://127\.0\.0\.1|http://(127\.0\.0\.1|localhost)",
        re.IGNORECASE,
    )),
    # Deserialization and template attacks
    ("ssti", re.compile(rb"\{\{[^}]+\}\}|\$\{[^}]+\}", re.IGNORECASE)),
    ("deserialization-java", re.compile(
        rb"rO0AB|java\.io\.ObjectInputStream|ysoserial|CommonsCollections",
        re.IGNORECASE,
    )),
    ("deserialization-dotnet", re.compile(
        rb"System\.Runtime\.Serialization|BinaryFormatter|LosFormatter|__VIEWSTATE",
        re.IGNORECASE,
    )),
    # Known exploit families
    ("log4shell", re.compile(
        rb"\$\{jndi\s*:|%24%7Bjndi|\$\{\$\{::-j\}\$\{::-n\}\$\{::-d\}\$\{::-i\}",
        re.IGNORECASE,
    )),
    ("spring4shell", re.compile(
        rb"class\.module\.classLoader|ClassLoader\.resources\.dirContext",
        re.IGNORECASE,
    )),
    ("shellshock", re.compile(rb"\(\)\s*\{\s*:;\s*\}", re.IGNORECASE)),
    ("proxy-abuse", re.compile(rb"^CONNECT\s+\S+:\d+\s+HTTP/", re.IGNORECASE | re.MULTILINE)),
    ("xxe", re.compile(
        rb"<!ENTITY\s+\S+\s+SYSTEM\s+[\"']|<!DOCTYPE\s+\S+\s+\[",
        re.IGNORECASE,
    )),
    # Credential access and brute force indicators
    ("weak-creds", re.compile(
        rb"\b(admin|root|test|guest|oracle|sa):(admin|password|123456|root|toor|pass|test|letmein|changeme)\b",
        re.IGNORECASE,
    )),
    ("password-spray", re.compile(
        rb"(invalid\s+password|login\s+failed|authentication\s+failed).*(admin|root|user|guest)",
        re.IGNORECASE,
    )),
    ("mimikatz", re.compile(
        rb"sekurlsa::|lsadump::|privilege::debug|token::elevate|kerberos::(ptt|golden)",
        re.IGNORECASE,
    )),
    # Recon/scanner/tool marks
    ("scanner", re.compile(
        rb"\b(nmap|masscan|zgrab|nuclei|nikto|sqlmap|dirbuster|gobuster|wfuzz|hydra|medusa|metasploit|amass|whatweb)\b",
        re.IGNORECASE,
    )),
    ("user-agent-scanner", re.compile(
        rb"user-agent\s*:\s*(sqlmap|nmap|masscan|nikto|acunetix|nessus)",
        re.IGNORECASE,
    )),
    # DoS / DDoS signatures
    ("dos-http-flood", re.compile(
        rb"(GET|POST)\s+/\S*\s+HTTP/1\.[01]\r\n(?:[^\r\n]+\r\n){20,}",
        re.IGNORECASE,
    )),
    ("dos-syn-flood", re.compile(rb"\x02$")),
    ("dos-udp-amplification", re.compile(
        rb"\x00\x00\x00\x00\x00\x01\x00\x00|\x17\x00\x03\x2a|\x01\x00\x00\x01\x00\x00",
        re.IGNORECASE,
    )),
    # Protocol abuse and OT
    ("dns-axfr", re.compile(rb"[\x00-\xff]{2}\x00\xfc")),
    ("heartbleed", re.compile(rb"\x18\x03[\x00-\x03]")),
    ("modbus", re.compile(rb"^\x00[\x00-\xff]\x00\x00[\x00-\xff]{2}[\x01-\x10]", re.MULTILINE)),
    ("smb-exec", re.compile(
        rb"(psexec|wmiexec|smbexec|\\\\.*\\ADMIN\$)",
        re.IGNORECASE,
    )),
    # Webshell / staged payload markers
    ("webshell", re.compile(
        rb"(system|exec|passthru|shell_exec)\s*\(|eval\s*\(\s*base64_decode\s*\(|assert\s*\(\s*\$_(POST|GET)",
        re.IGNORECASE,
    )),
    ("webshell-china-chopper", re.compile(
        rb"\bpass\s*=\s*\"[a-z0-9]{3,8}\".*(eval|assert)\s*\(",
        re.IGNORECASE,
    )),
]

FIELDNAMES = [
    "event_key",
    "hit_count",
    "timestamp_utc",
    "last_seen_utc",
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
    "http_method",
    "http_uri",
    "http_version",
    "http_host",
    "http_user_agent",
    "http_referer",
    "http_status_code",
    "http_content_type",
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
        self._tcp_sessions: Dict[tuple[str, str, str, str], Dict[str, int | bool]] = {}
        self.pg_conn = None
        self.pg_cursor = None
        self._exempt_networks = self._load_exempt_networks()
        self._exempt_asns = self._load_exempt_asns()
        self._self_ip = self._fetch_self_ip()

        if self._effective_postgres_dsn():
            self._init_postgres()

    def _fetch_self_ip(self) -> str:
        """Fetch this host's public IP via ipify and return it as a string."""
        try:
            with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=5) as resp:
                data = json.loads(resp.read().decode())
                ip = data["ip"]
                print(f"[*] Self public IP: {ip} (outgoing packets from this IP will be ignored)", flush=True)
                return ip
        except Exception as exc:
            print(f"[!] Could not fetch self IP from ipify: {exc} — outgoing-packet filter disabled", flush=True)
            return ""

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
                    event_key TEXT UNIQUE,
                    hit_count BIGINT DEFAULT 1,
                    timestamp_utc TIMESTAMPTZ,
                    last_seen_utc TIMESTAMPTZ,
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
                    attack_tags TEXT,
                    http_method TEXT,
                    http_uri TEXT,
                    http_version TEXT,
                    http_host TEXT,
                    http_user_agent TEXT,
                    http_referer TEXT,
                    http_status_code TEXT,
                    http_content_type TEXT
                )
                """
            )
            self.pg_cursor.execute(
                f"ALTER TABLE {POSTGRES_TABLE} ADD COLUMN IF NOT EXISTS source_name TEXT"
            )
            self.pg_cursor.execute(
                f"ALTER TABLE {POSTGRES_TABLE} ADD COLUMN IF NOT EXISTS attack_tags TEXT"
            )
            self.pg_cursor.execute(
                f"ALTER TABLE {POSTGRES_TABLE} ADD COLUMN IF NOT EXISTS event_key TEXT"
            )
            self.pg_cursor.execute(
                f"ALTER TABLE {POSTGRES_TABLE} ADD COLUMN IF NOT EXISTS hit_count BIGINT DEFAULT 1"
            )
            self.pg_cursor.execute(
                f"ALTER TABLE {POSTGRES_TABLE} ADD COLUMN IF NOT EXISTS last_seen_utc TIMESTAMPTZ"
            )
            for _col, _type in (
                ("http_method", "TEXT"),
                ("http_uri", "TEXT"),
                ("http_version", "TEXT"),
                ("http_host", "TEXT"),
                ("http_user_agent", "TEXT"),
                ("http_referer", "TEXT"),
                ("http_status_code", "TEXT"),
                ("http_content_type", "TEXT"),
            ):
                self.pg_cursor.execute(
                    f"ALTER TABLE {POSTGRES_TABLE} ADD COLUMN IF NOT EXISTS {_col} {_type}"
                )
            self.pg_cursor.execute(
                f"CREATE UNIQUE INDEX IF NOT EXISTS idx_{POSTGRES_TABLE}_event_key ON {POSTGRES_TABLE}(event_key)"
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

    def _load_exempt_asns(self) -> set[str]:
        asns: set[str] = set()
        if not EXEMPT_ASNS_FILE or not os.path.isfile(EXEMPT_ASNS_FILE):
            return asns

        with open(EXEMPT_ASNS_FILE, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue

                normalized = line.upper()
                if normalized.startswith("AS"):
                    normalized = normalized[2:]

                if normalized.isdigit():
                    asns.add(normalized)
                else:
                    print(f"[!] Skipping invalid exempt ASN entry: {line!r}", flush=True)

        print(f"[*] Loaded {len(asns)} exempt ASN(s) from {EXEMPT_ASNS_FILE}", flush=True)
        return asns

    def _is_exempt(self, ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(ip_obj in net for net in self._exempt_networks)

    def _is_exempt_asn(self, asn_value: str) -> bool:
        if not asn_value:
            return False
        normalized = asn_value.upper().strip()
        if normalized.startswith("AS"):
            normalized = normalized[2:]
        return normalized in self._exempt_asns

    def _is_local_ip(self, ip_str: str) -> bool:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        )

    def _tcp_session_key(self, rec: IntelRecord) -> tuple[str, str, str, str]:
        return (rec.src_ip, rec.src_port, rec.dst_ip, rec.dst_port)

    def _tcp_ack_value(self, tcp_layer, payload_len: int) -> int:
        flags = str(tcp_layer.flags)
        ack_value = int(tcp_layer.seq) + payload_len
        if "S" in flags:
            ack_value += 1
        if "F" in flags:
            ack_value += 1
        return ack_value

    def _service_reply_payload(self, service_guess: str, payload: bytes) -> bytes:
        normalized = service_guess or ""
        if HTTP_REQUEST_RE.search(payload):
            return HTTP_200_RESPONSE
        banner = SERVICE_BANNERS.get(normalized)
        if banner:
            return banner
        return HTTP_200_RESPONSE

    def _reply_to_packet(self, pkt, rec: IntelRecord):
        if rec.transport != "TCP" or TCP not in pkt:
            return
        if self._is_local_ip(rec.src_ip) or self._is_local_ip(rec.dst_ip):
            return
        if self._self_ip and rec.src_ip == self._self_ip:
            return
        if self._is_exempt(rec.src_ip) or self._is_exempt(rec.dst_ip):
            return

        tcp_layer = pkt[TCP]
        flags = str(tcp_layer.flags)
        key = self._tcp_session_key(rec)

        if "R" in flags:
            self._tcp_sessions.pop(key, None)
            return
        if len(self._tcp_sessions) > 10000:
            self._tcp_sessions.clear()

        if IP in pkt:
            network_layer = IP(src=rec.dst_ip, dst=rec.src_ip)
        elif IPv6 in pkt:
            network_layer = IPv6(src=rec.dst_ip, dst=rec.src_ip)
        else:
            return

        payload_len = len(rec.payload)
        if "S" in flags and "A" not in flags:
            server_seq = random.randint(0, (1 << 32) - 1)
            self._tcp_sessions[key] = {
                "server_seq": server_seq + 1,
                "responded": False,
            }
            syn_ack = TCP(
                sport=int(rec.dst_port),
                dport=int(rec.src_port),
                flags="SA",
                seq=server_seq,
                ack=int(tcp_layer.seq) + 1,
            )
            send(network_layer / syn_ack, verbose=False)
            return

        session = self._tcp_sessions.get(key)
        if session is None:
            session = {
                "server_seq": random.randint(0, (1 << 32) - 1),
                "responded": False,
            }
            self._tcp_sessions[key] = session

        if session["responded"]:
            if "F" in flags or "R" in flags:
                self._tcp_sessions.pop(key, None)
            return

        service_guess = self._service_guess(rec.dst_port, rec.src_port, rec.payload)
        should_reply = payload_len > 0 or service_guess in BANNER_FIRST_SERVICES or "A" in flags
        if not should_reply:
            return

        reply_payload = self._service_reply_payload(service_guess, rec.payload)
        reply = TCP(
            sport=int(rec.dst_port),
            dport=int(rec.src_port),
            flags="PA",
            seq=int(session["server_seq"]),
            ack=self._tcp_ack_value(tcp_layer, payload_len),
        )
        send(network_layer / reply / Raw(load=reply_payload), verbose=False)
        session["server_seq"] = int(session["server_seq"]) + len(reply_payload)
        session["responded"] = True
        if "F" in flags or service_guess not in BANNER_FIRST_SERVICES:
            fin = TCP(
                sport=int(rec.dst_port),
                dport=int(rec.src_port),
                flags="FA",
                seq=int(session["server_seq"]),
                ack=self._tcp_ack_value(tcp_layer, payload_len),
            )
            send(network_layer / fin, verbose=False)
            self._tcp_sessions.pop(key, None)

    def _write_postgres(self, row: Dict[str, str]):
        if self.pg_cursor is None:
            return

        try:
            self.pg_cursor.execute(
                f"""
                INSERT INTO {POSTGRES_TABLE} (
                    source_name, event_key, hit_count, timestamp_utc, last_seen_utc,
                    src_ip, dst_ip, src_port, dst_port, transport,
                    ip_proto, packet_len, ttl_hoplimit, tcp_flags, service_guess,
                    is_scan_like, ioc_ips, ioc_domains, ioc_urls, ioc_hashes,
                    ioc_cves, payload_sha256, payload_b64, rdns, is_private,
                    is_reserved, is_multicast, country, asn, asn_description,
                    whois_network, attack_tags,
                    http_method, http_uri, http_version, http_host,
                    http_user_agent, http_referer, http_status_code, http_content_type
                ) VALUES (
                    %(source_name)s, %(event_key)s, %(hit_count)s, %(timestamp_utc)s, %(last_seen_utc)s,
                    %(src_ip)s, %(dst_ip)s, %(src_port)s,
                    %(dst_port)s, %(transport)s, %(ip_proto)s, %(packet_len)s,
                    %(ttl_hoplimit)s, %(tcp_flags)s, %(service_guess)s,
                    %(is_scan_like_bool)s, %(ioc_ips)s, %(ioc_domains)s,
                    %(ioc_urls)s, %(ioc_hashes)s, %(ioc_cves)s,
                    %(payload_sha256)s, %(payload_b64)s, %(rdns)s,
                    %(is_private_bool)s, %(is_reserved_bool)s,
                    %(is_multicast_bool)s, %(country)s, %(asn)s,
                    %(asn_description)s, %(whois_network)s, %(attack_tags)s,
                    %(http_method)s, %(http_uri)s, %(http_version)s, %(http_host)s,
                    %(http_user_agent)s, %(http_referer)s, %(http_status_code)s, %(http_content_type)s
                )
                ON CONFLICT (event_key)
                DO UPDATE SET
                    hit_count = {POSTGRES_TABLE}.hit_count + 1,
                    last_seen_utc = EXCLUDED.last_seen_utc,
                    src_ip = EXCLUDED.src_ip,
                    src_port = EXCLUDED.src_port,
                    packet_len = EXCLUDED.packet_len,
                    ttl_hoplimit = EXCLUDED.ttl_hoplimit,
                    tcp_flags = EXCLUDED.tcp_flags,
                    rdns = EXCLUDED.rdns,
                    is_private = EXCLUDED.is_private,
                    is_reserved = EXCLUDED.is_reserved,
                    is_multicast = EXCLUDED.is_multicast,
                    country = EXCLUDED.country,
                    asn = EXCLUDED.asn,
                    asn_description = EXCLUDED.asn_description,
                    whois_network = EXCLUDED.whois_network
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

    def _extract_http_fields(self, payload: bytes) -> Dict[str, str]:
        empty: Dict[str, str] = {
            "http_method": "",
            "http_uri": "",
            "http_version": "",
            "http_host": "",
            "http_user_agent": "",
            "http_referer": "",
            "http_status_code": "",
            "http_content_type": "",
        }
        if not payload:
            return empty
        result = dict(empty)
        m = HTTP_REQUEST_RE.search(payload)
        if m:
            result["http_method"] = m.group(1).decode("utf-8", errors="ignore").upper()
            result["http_uri"] = m.group(2).decode("utf-8", errors="ignore")[:512]
            result["http_version"] = m.group(3).decode("utf-8", errors="ignore")
        else:
            m = HTTP_RESPONSE_RE.search(payload)
            if m:
                result["http_version"] = m.group(1).decode("utf-8", errors="ignore")
                result["http_status_code"] = m.group(2).decode("utf-8", errors="ignore")
        for field, regex in (
            ("http_host", HTTP_HOST_RE),
            ("http_user_agent", HTTP_UA_RE),
            ("http_referer", HTTP_REFERER_RE),
            ("http_content_type", HTTP_CONTENT_TYPE_RE),
        ):
            hm = regex.search(payload)
            if hm:
                result[field] = hm.group(1).decode("utf-8", errors="ignore")[:256]
        return result

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

    def _event_key(self, rec: IntelRecord, payload_sha256: str, service_guess: str, attack_tags: str, ioc_info: Dict[str, str]) -> str:
        # Exclude source IP to collapse distributed flood traffic into one grouped event.
        key_parts = [
            rec.dst_ip,
            rec.dst_port,
            rec.transport,
            rec.ip_proto,
            rec.tcp_flags,
            service_guess,
            attack_tags,
            payload_sha256,
            ioc_info.get("ioc_urls", ""),
            ioc_info.get("ioc_domains", ""),
            ioc_info.get("ioc_hashes", ""),
            ioc_info.get("ioc_cves", ""),
        ]
        raw = "|".join(key_parts)
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()

    def write_record(self, rec: IntelRecord):
        if self._is_local_ip(rec.src_ip) or self._is_local_ip(rec.dst_ip):
            return
        if self._self_ip and rec.src_ip == self._self_ip:
            return  # outgoing packet from this host — ignore
        if self._is_exempt(rec.src_ip) or self._is_exempt(rec.dst_ip):
            return

        src_ip_obj = ipaddress.ip_address(rec.src_ip)
        ioc_info = self._extract_iocs(rec.payload)
        http_fields = self._extract_http_fields(rec.payload)
        rdns = self._safe_rdns(rec.src_ip)
        rdap = self._safe_rdap(rec.src_ip) if src_ip_obj.is_global else {
            "country": "",
            "asn": "",
            "asn_description": "",
            "whois_network": "",
        }
        if self._is_exempt_asn(rdap["asn"]):
            return

        now_iso = datetime.now(timezone.utc).isoformat()
        service_guess = self._service_guess(rec.dst_port, rec.src_port, rec.payload)
        payload_sha256 = hashlib.sha256(rec.payload).hexdigest() if rec.payload else ""
        attack_tags = self._detect_attack_type(rec.payload)
        event_key = self._event_key(rec, payload_sha256, service_guess, attack_tags, ioc_info)

        row = {
            "source_name": SOURCE_NAME,
            "event_key": event_key,
            "hit_count": 1,
            "timestamp_utc": now_iso,
            "last_seen_utc": now_iso,
            "src_ip": rec.src_ip,
            "dst_ip": rec.dst_ip,
            "src_port": rec.src_port,
            "dst_port": rec.dst_port,
            "transport": rec.transport,
            "ip_proto": rec.ip_proto,
            "packet_len": rec.packet_len,
            "ttl_hoplimit": rec.ttl_hoplimit,
            "tcp_flags": rec.tcp_flags,
            "service_guess": service_guess,
            "is_scan_like": self._is_scan_like(rec.transport, rec.tcp_flags, len(rec.payload)),
            "payload_sha256": payload_sha256,
            "payload_b64": "encrypted" if self._is_encrypted_payload(rec.payload) else (base64.b64encode(rec.payload).decode("ascii") if rec.payload else ""),
            "rdns": rdns,
            "is_private": str(src_ip_obj.is_private).lower(),
            "is_reserved": str(src_ip_obj.is_reserved).lower(),
            "is_multicast": str(src_ip_obj.is_multicast).lower(),
            "country": rdap["country"],
            "asn": rdap["asn"],
            "asn_description": rdap["asn_description"],
            "whois_network": rdap["whois_network"],
            "attack_tags": attack_tags,
        }
        row.update(ioc_info)
        row.update(http_fields)

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
            collector._reply_to_packet(pkt, rec)
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
