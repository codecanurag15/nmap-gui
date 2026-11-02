#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NmapGUI - a complete graphical front-end for Nmap (Kali Linux)

  * every Nmap option is exposed with its real flag name (same flags, same modes)
  * live colourised console, animated progress bar, results tree
  * the HTML report is written ONLY when you press "Save HTML report" (default folder: ./reports)

Run:     sudo -E python3 nmap_gui.py
Needs:   sudo apt install nmap python3-pyqt5
Fonts (optional, nicer look):  sudo apt install fonts-hack fonts-jetbrains-mono

Use it only on systems you own or are explicitly authorised to test.
"""
import sys, os, re, shlex, html, math, random, shutil, tempfile, datetime, subprocess
import xml.etree.ElementTree as ET

from PyQt5.QtCore import (Qt, QTimer, QProcess, QPointF, QRectF, QPropertyAnimation, QEasingCurve,
                          QVariantAnimation, QElapsedTimer, pyqtSignal)
from PyQt5.QtGui import (QPainter, QColor, QPen, QBrush, QFont, QFontMetrics, QFontDatabase, QPalette,
                         QLinearGradient, QRadialGradient, QConicalGradient, QPainterPath,
                         QTextCharFormat, QSyntaxHighlighter, QTextCursor)
from PyQt5.QtWidgets import (QApplication, QWidget, QFrame, QLabel, QLineEdit, QPushButton, QCheckBox,
                             QComboBox, QVBoxLayout, QHBoxLayout, QGridLayout, QSplitter, QTabWidget,
                             QScrollArea, QPlainTextEdit, QTreeWidget, QTreeWidgetItem, QFileDialog,
                             QMessageBox, QInputDialog, QMenu, QGraphicsDropShadowEffect,
                             QGraphicsOpacityEffect, QButtonGroup)

APP_NAME = "NmapGUI"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(BASE_DIR, "reports")     # saved reports land here, next to this script
CYAN, MAG, VIO = "#00e5ff", "#ff2bd6", "#7c4dff"
GRN, RED, YEL = "#39ff88", "#ff4d6d", "#ffd166"
TXT, DIM = "#d7e3ff", "#7d8bb5"
FONT_MONO = "monospace"      # resolved in main()
FONT_UI = "sans-serif"

# ───────────────────────────── Nmap option catalogue ─────────────────────────────
# (flag, kind, description, hint, choices)
#   kind: flag = plain switch | arg = "flag value" | att = "flagVALUE" (e.g. -PS80,443)
#         file = arg with file picker | sel = drop-down of ready-made flags
TCP_MODES = [
    ("", "default", "Nmap picks: SYN scan as root, connect scan otherwise"),
    ("-sS", "SYN stealth", "Half-open TCP SYN scan (needs root)"),
    ("-sT", "TCP connect", "Full TCP connect() scan"),
    ("-sA", "ACK", "ACK scan - maps firewall rule sets"),
    ("-sW", "Window", "TCP Window scan"),
    ("-sM", "Maimon", "Maimon scan (FIN/ACK)"),
    ("-sN", "Null", "Null scan - no TCP flags set"),
    ("-sF", "FIN", "FIN scan"),
    ("-sX", "Xmas", "Xmas scan - FIN, PSH and URG set"),
    ("-sY", "SCTP INIT", "SCTP INIT scan"),
    ("-sZ", "SCTP COOKIE", "SCTP COOKIE-ECHO scan"),
]
NSE_CATS = ["auth", "broadcast", "brute", "default", "discovery", "dos", "exploit",
            "external", "fuzzer", "intrusive", "malware", "safe", "version", "vuln"]
T_CHOICES = [("-T%d  %s" % (i, n), "-T%d" % i) for i, n in
             enumerate(["Paranoid", "Sneaky", "Polite", "Normal", "Aggressive", "Insane"])]

OPT_TABS = [
    ("Target", [
        "Target specification",
        ("-iL", "file", "Read targets from a file", "targets.txt"),
        ("-iR", "arg", "Scan N random hosts", "count"),
        ("--exclude", "arg", "Exclude hosts / networks", "host1,10.0.0.0/24"),
        ("--excludefile", "file", "Exclude targets listed in a file", ""),
        ("--randomize-hosts", "flag", "Randomize target order"),
        ("-6", "flag", "Enable IPv6 scanning"),
    ]),
    ("Discovery", [
        "Scan mode",
        ("-sn", "flag", "Ping scan only, no port scan"),
        ("-sL", "flag", "List scan, just list the targets"),
        ("-Pn", "flag", "Skip host discovery, treat all as up"),
        "Discovery probes",
        ("-PS", "att", "TCP SYN ping", "ports, e.g. 22,80,443"),
        ("-PA", "att", "TCP ACK ping", "ports, e.g. 80,3389"),
        ("-PU", "att", "UDP ping", "ports, e.g. 40125"),
        ("-PY", "att", "SCTP INIT ping", "ports"),
        ("-PO", "att", "IP protocol ping", "protocols, e.g. 1,2,4"),
        ("-PE", "flag", "ICMP echo ping"),
        ("-PP", "flag", "ICMP timestamp ping"),
        ("-PM", "flag", "ICMP netmask ping"),
        ("-PR", "flag", "ARP ping (local network)"),
        "Name resolution and path",
        ("-n", "flag", "Never resolve DNS"),
        ("-R", "flag", "Always resolve DNS"),
        ("--dns-servers", "arg", "Custom DNS servers", "ip1,ip2"),
        ("--system-dns", "flag", "Use the OS DNS resolver"),
        ("--traceroute", "flag", "Trace the hop path to each host"),
    ]),
    ("Scan", [
        "TCP scan technique", "@tcp",
        "Additional scan types",
        ("-sU", "flag", "UDP scan (combine with a TCP technique)"),
        ("-sO", "flag", "IP protocol scan"),
        ("-sI", "arg", "Idle (zombie) scan", "zombie[:probeport]"),
        ("-b", "arg", "FTP bounce scan", "user:pass@host:port"),
        ("--scanflags", "arg", "Custom TCP flags", "URGACKPSHRSTSYNFIN"),
    ]),
    ("Ports", [
        "Port selection",
        ("-p", "arg", "Port ranges", "1-1000,U:53,T:80"),
        ("-F", "flag", "Fast scan, fewer ports"),
        ("--top-ports", "arg", "Scan the N most common ports", "N"),
        ("--port-ratio", "arg", "Ports more common than ratio", "0.0 - 1.0"),
        ("--exclude-ports", "arg", "Exclude these ports", "ports"),
        ("-r", "flag", "Scan ports in order, no shuffling"),
    ]),
    ("Service / OS", [
        "Service and version detection",
        ("-sV", "flag", "Probe open ports for service/version"),
        ("--version-intensity", "arg", "Version probe intensity", "",
         [(str(i), str(i)) for i in range(10)]),
        ("--version-light", "flag", "Light probes (intensity 2)"),
        ("--version-all", "flag", "Try every probe (intensity 9)"),
        ("--version-trace", "flag", "Trace version scan activity"),
        "OS detection",
        ("-O", "flag", "Enable OS detection"),
        ("--osscan-limit", "flag", "Only try OS detection on promising hosts"),
        ("--osscan-guess", "flag", "Guess OS more aggressively"),
        ("--max-os-tries", "arg", "Max OS detection tries", "number"),
        "Everything at once",
        ("-A", "flag", "Aggressive: OS, version, scripts, traceroute"),
    ]),
    ("Scripts", [
        "Nmap Scripting Engine",
        ("-sC", "flag", "Run the default scripts"),
        ("--script", "arg", "Scripts, categories or expressions", "default,vuln  |  http-*"),
        "@cats",
        ("--script-args", "arg", "Script arguments", "k1=v1,k2=v2"),
        ("--script-args-file", "file", "Script arguments from a file", ""),
        ("--script-trace", "flag", "Trace all script traffic"),
    ]),
    ("Timing", [
        "Timing template",
        ("timing", "sel", "Overall timing and speed", "", T_CHOICES),
        "Parallelism",
        ("--min-hostgroup", "arg", "Min parallel host group size", "size"),
        ("--max-hostgroup", "arg", "Max parallel host group size", "size"),
        ("--min-parallelism", "arg", "Min probe parallelization", "n"),
        ("--max-parallelism", "arg", "Max probe parallelization", "n"),
        "Timeouts and retries",
        ("--min-rtt-timeout", "arg", "Min probe round-trip timeout", "e.g. 100ms"),
        ("--max-rtt-timeout", "arg", "Max probe round-trip timeout", "e.g. 1s"),
        ("--initial-rtt-timeout", "arg", "Initial probe timeout", "e.g. 500ms"),
        ("--max-retries", "arg", "Max probe retransmissions", "n"),
        ("--host-timeout", "arg", "Give up on a host after", "e.g. 30m"),
        "Rate control",
        ("--scan-delay", "arg", "Delay between probes", "e.g. 5ms"),
        ("--max-scan-delay", "arg", "Max delay between probes", "e.g. 1s"),
        ("--min-rate", "arg", "Send no slower than N pkts/s", "n"),
        ("--max-rate", "arg", "Send no faster than N pkts/s", "n"),
        ("--defeat-rst-ratelimit", "flag", "Ignore RST rate limiting"),
        ("--defeat-icmp-ratelimit", "flag", "Ignore ICMP rate limiting"),
    ]),
    ("Evasion", [
        "Firewall / IDS evasion and spoofing",
        ("-f", "flag", "Fragment packets"),
        ("--mtu", "arg", "Custom fragment MTU", "multiple of 8"),
        ("-D", "arg", "Cloak the scan with decoys", "RND:10,decoy1,ME"),
        ("-S", "arg", "Spoof source address", "IP"),
        ("-e", "arg", "Use this network interface", "eth0"),
        ("-g", "arg", "Spoof source port", "port"),
        ("--proxies", "arg", "Relay through HTTP/SOCKS4 proxies", "url1,url2"),
        ("--data", "arg", "Append custom hex payload", "hex string"),
        ("--data-string", "arg", "Append custom ASCII payload", "text"),
        ("--data-length", "arg", "Append random data", "bytes"),
        ("--ip-options", "arg", "Send packets with IP options", "R | T | U | L ..."),
        ("--ttl", "arg", "Set IP time-to-live", "value"),
        ("--spoof-mac", "arg", "Spoof MAC address", "MAC | prefix | vendor | 0"),
        ("--badsum", "flag", "Send packets with a bogus checksum"),
    ]),
    ("Output / Misc", [
        "Verbosity and debugging",
        ("verbosity", "sel", "Verbosity level", "",
         [("-v  verbose", "-v"), ("-vv  more verbose", "-vv"), ("-vvv  most verbose", "-vvv")]),
        ("debug", "sel", "Debugging level", "",
         [("-d", "-d"), ("-dd", "-dd"), ("-d3", "-d3"), ("-d9", "-d9")]),
        ("--reason", "flag", "Show the reason for each port state"),
        ("--open", "flag", "Show only open (or possibly open) ports"),
        ("--packet-trace", "flag", "Show every packet sent and received"),
        "Miscellaneous",
        ("--datadir", "arg", "Custom Nmap data directory", "dir"),
        ("--send-eth", "flag", "Send raw ethernet frames"),
        ("--send-ip", "flag", "Send raw IP packets"),
        ("--privileged", "flag", "Assume full privileges"),
        ("--unprivileged", "flag", "Assume no raw-socket privileges"),
        ("--nsock-engine", "arg", "Nsock IO engine", "",
         [("epoll", "epoll"), ("poll", "poll"), ("select", "select")]),
        ("--release-memory", "flag", "Release memory before quitting"),
    ]),
]

# Zenmap-style presets -> option key: value
PROFILES = {
    "- Custom -": {},
    "Intense scan": {"timing": "-T4", "-A": True, "verbosity": "-v"},
    "Intense scan + UDP": {"tcp": "-sS", "-sU": True, "timing": "-T4", "-A": True, "verbosity": "-v"},
    "Intense scan, all TCP ports": {"-p": "1-65535", "timing": "-T4", "-A": True, "verbosity": "-v"},
    "Intense scan, no ping": {"timing": "-T4", "-A": True, "verbosity": "-v", "-Pn": True},
    "Ping scan": {"-sn": True},
    "Quick scan": {"timing": "-T4", "-F": True},
    "Quick scan plus": {"-sV": True, "timing": "-T4", "-O": True, "-F": True, "--version-light": True},
    "Quick traceroute": {"-sn": True, "--traceroute": True},
    "Regular scan": {},
    "Slow comprehensive scan": {"tcp": "-sS", "-sU": True, "timing": "-T4", "-A": True, "verbosity": "-v",
                                "-PE": True, "-PP": True, "-PS": "80,443", "-PA": "3389", "-PU": "40125",
                                "-PY": "", "-g": "53", "--script": "default or (discovery and safe)"},
}

# ───────────────────────────── stylesheet ─────────────────────────────
QSS = """
QWidget { color:$TXT; font-family:"$UI"; font-size:13px; }
QToolTip { background:#0b1230; color:$TXT; border:1px solid $CYAN; padding:6px; }
QFrame#glass { background:rgba(9,14,36,178); border:1px solid rgba(0,229,255,70); border-radius:14px; }
QFrame#card { background:rgba(9,14,36,178); border:1px solid rgba(124,77,255,120); border-radius:12px; }
QLabel#cardTitle { color:$DIM; font-size:11px; }
QLabel#cardValue { font-family:"$MONO"; font-size:24px; font-weight:bold; }
QLabel#desc { color:$DIM; }
QLabel#section { color:$CYAN; font-size:12px; font-weight:bold; padding:10px 0 2px 2px; }
QLabel#dim { color:$DIM; }
QLineEdit, QComboBox { background:rgba(4,8,24,210); border:1px solid rgba(0,229,255,60); border-radius:8px; padding:6px 9px; selection-background-color:$VIO; }
QLineEdit:focus, QComboBox:focus { border:1px solid $CYAN; background:rgba(6,12,34,238); }
QLineEdit:disabled, QComboBox:disabled { color:#46527c; border:1px solid rgba(255,255,255,20); }
QLineEdit#target { font-family:"$MONO"; font-size:15px; padding:10px 14px; border:1px solid rgba(255,43,214,130); }
QLineEdit#target:focus { border:1px solid $MAG; }
QLineEdit#cmd { font-family:"$MONO"; color:$GRN; }
QLineEdit#extra { font-family:"$MONO"; }
QComboBox::drop-down { border:none; width:22px; }
QComboBox QAbstractItemView { background:#0b1230; border:1px solid $CYAN; selection-background-color:#18307a; outline:0; }
QCheckBox { spacing:8px; }
QCheckBox#flagcb { font-family:"$MONO"; font-weight:bold; }
QCheckBox::indicator { width:16px; height:16px; border-radius:4px; border:1px solid rgba(0,229,255,140); background:rgba(4,8,24,210); }
QCheckBox::indicator:hover { border:1px solid $CYAN; }
QCheckBox::indicator:checked { border:1px solid $CYAN; background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 $CYAN,stop:1 $VIO); }
QPushButton { background:rgba(255,255,255,14); border:1px solid rgba(0,229,255,70); border-radius:9px; padding:8px 16px; }
QPushButton:hover { background:rgba(0,229,255,40); border:1px solid $CYAN; }
QPushButton:pressed { background:rgba(0,229,255,85); }
QPushButton:disabled { color:#46527c; border:1px solid rgba(255,255,255,18); background:rgba(255,255,255,6); }
QPushButton::menu-indicator { image:none; }
QPushButton#mini { padding:6px 0; }
QPushButton#start { font-weight:bold; font-size:15px; padding:11px 28px; color:#02121a; border:none; background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 $CYAN,stop:1 $GRN); }
QPushButton#start:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #5af0ff,stop:1 #7dffb0); }
QPushButton#start:disabled { color:#0a2230; background:#27465c; }
QPushButton#stop { font-weight:bold; padding:11px 22px; color:$RED; border:1px solid $RED; }
QPushButton#stop:hover { background:rgba(255,77,109,60); }
QPushButton#stop:disabled { color:#5a3a46; border:1px solid #3a2a34; }
QPushButton#save { font-weight:bold; color:#16041f; border:none; padding:8px 20px; background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 $MAG,stop:1 $VIO); }
QPushButton#save:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #ff6be6,stop:1 #9b7bff); }
QPushButton#save:disabled { color:#5b4a73; background:rgba(255,255,255,10); border:1px solid rgba(255,255,255,18); }
QPushButton#chip { font-family:"$MONO"; font-size:11px; padding:7px 4px; border-radius:10px; }
QPushButton#chip:checked { color:white; border:1px solid $CYAN; background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(0,229,255,150),stop:1 rgba(124,77,255,175)); }
QPushButton#cat { padding:4px 11px; border-radius:12px; font-size:12px; }
QPushButton#cat:checked { color:white; border:1px solid $MAG; background:rgba(255,43,214,125); }
QTabWidget::pane { border:1px solid rgba(0,229,255,45); border-radius:10px; background:rgba(5,9,26,120); top:-1px; }
QTabBar::tab { background:rgba(255,255,255,10); color:$DIM; padding:8px 13px; margin-right:3px; border-top-left-radius:9px; border-top-right-radius:9px; }
QTabBar::tab:hover { color:white; background:rgba(0,229,255,28); }
QTabBar::tab:selected { color:white; background:rgba(0,229,255,48); border-bottom:2px solid $CYAN; }
QPlainTextEdit#console { background:rgba(3,6,18,218); border:none; border-radius:10px; padding:8px; selection-background-color:$VIO; font-family:"$MONO"; font-size:12px; }
QAbstractItemView { background:#0b1230; }
QTreeWidget { background:rgba(3,6,18,205); alternate-background-color:rgba(255,255,255,8); border:none; border-radius:10px; font-family:"$MONO"; font-size:12px; }
QTreeWidget::item { padding:3px; }
QTreeWidget::item:selected { background:rgba(124,77,255,115); }
QHeaderView::section { background:rgba(0,229,255,32); color:$CYAN; border:none; padding:6px; font-weight:bold; }
QScrollArea { background:transparent; border:none; }
QScrollBar:vertical { background:transparent; width:10px; margin:2px; }
QScrollBar::handle:vertical { background:rgba(0,229,255,90); border-radius:4px; min-height:30px; }
QScrollBar::handle:vertical:hover { background:$CYAN; }
QScrollBar:horizontal { background:transparent; height:10px; margin:2px; }
QScrollBar::handle:horizontal { background:rgba(0,229,255,90); border-radius:4px; min-width:30px; }
QScrollBar::add-line, QScrollBar::sub-line { height:0; width:0; }
QScrollBar::add-page, QScrollBar::sub-page { background:transparent; }
QSplitter::handle { background:transparent; }
QMenu { background:#0b1230; border:1px solid $CYAN; padding:6px; }
QMenu::item { padding:7px 22px; border-radius:6px; }
QMenu::item:selected { background:rgba(0,229,255,55); }
"""


def build_qss():
    s = QSS
    for k, v in (("$TXT", TXT), ("$DIM", DIM), ("$CYAN", CYAN), ("$MAG", MAG), ("$VIO", VIO),
                 ("$GRN", GRN), ("$RED", RED), ("$MONO", FONT_MONO), ("$UI", FONT_UI)):
        s = s.replace(k, v)
    return s


# ───────────────────────────── XML parsing / HTML report ─────────────────────────────
def parse_xml(path):
    """Parse Nmap's XML output into plain dicts."""
    root = ET.parse(path).getroot()
    d = {"version": root.get("version", ""), "args": root.get("args", ""), "start": root.get("startstr", ""),
         "hosts": [], "elapsed": "", "summary": "", "up": None, "down": 0}
    fin = root.find("runstats/finished")
    if fin is not None:
        d["elapsed"], d["summary"] = fin.get("elapsed", ""), fin.get("summary", "")
    hs = root.find("runstats/hosts")
    if hs is not None:
        d["up"], d["down"] = int(hs.get("up", 0)), int(hs.get("down", 0))
    for h in root.findall("host"):
        st = h.find("status")
        host = {"state": st.get("state", "") if st is not None else "", "ip": "", "mac": "", "vendor": "",
                "names": [], "ports": [], "os": [], "trace": [], "scripts": [], "extra": [], "uptime": ""}
        for a in h.findall("address"):
            t = a.get("addrtype")
            if t in ("ipv4", "ipv6"):
                host["ip"] = a.get("addr", "")
            elif t == "mac":
                host["mac"], host["vendor"] = a.get("addr", ""), a.get("vendor", "")
        host["names"] = [n.get("name", "") for n in h.findall("hostnames/hostname")]
        for e in h.findall("ports/extraports"):
            host["extra"].append("%s %s" % (e.get("count", "?"), e.get("state", "")))
        for p in h.findall("ports/port"):
            stt, sv = p.find("state"), p.find("service")
            svc = ver = ""
            if sv is not None:
                svc = sv.get("name", "") + (" (ssl)" if sv.get("tunnel") == "ssl" else "")
                bits = [sv.get("product", ""), sv.get("version", "")]
                if sv.get("extrainfo"):
                    bits.append("(%s)" % sv.get("extrainfo"))
                ver = " ".join(b for b in bits if b)
            host["ports"].append({
                "port": p.get("portid", ""), "proto": p.get("protocol", ""),
                "state": stt.get("state", "") if stt is not None else "",
                "reason": stt.get("reason", "") if stt is not None else "",
                "service": svc, "version": ver,
                "scripts": [(s.get("id", ""), s.get("output", "")) for s in p.findall("script")]})
        host["os"] = [(m.get("name", ""), m.get("accuracy", "")) for m in h.findall("os/osmatch")]
        host["trace"] = [(x.get("ttl", ""), x.get("ipaddr", ""), x.get("rtt", ""), x.get("host", ""))
                         for x in h.findall("trace/hop")]
        host["scripts"] = [(s.get("id", ""), s.get("output", "")) for s in h.findall("hostscript/script")]
        up = h.find("uptime")
        if up is not None:
            host["uptime"] = up.get("lastboot", "") or ("%s s" % up.get("seconds", ""))
        d["hosts"].append(host)
    if d["up"] is None:
        d["up"] = sum(1 for h in d["hosts"] if h["state"] == "up")
    return d


def count_open(d):
    return sum(1 for h in d["hosts"] for p in h["ports"] if p["state"] == "open")


HTML_CSS = """
:root{--bg:#070b1a;--card:#0e1530;--line:#1d2b5c;--txt:#d7e3ff;--dim:#7d8bb5;--cy:#00e5ff;--mg:#ff2bd6;--vi:#7c4dff;--gr:#39ff88;--rd:#ff4d6d;--yl:#ffd166}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1100px 600px at 8% -10%,#1b1050 0,transparent 60%),radial-gradient(900px 500px at 100% 0,#06324a 0,transparent 55%),var(--bg);color:var(--txt);font:14px/1.55 'Segoe UI',Ubuntu,'Noto Sans',sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:34px 20px 60px}
h1{margin:0;font-size:36px;background:linear-gradient(90deg,var(--cy),var(--vi),var(--mg));-webkit-background-clip:text;background-clip:text;color:transparent}
.sub{color:var(--dim);margin:6px 0 22px;font-size:13px}
.cmd{font-family:ui-monospace,'DejaVu Sans Mono',monospace;background:#050914;border:1px solid var(--line);border-left:3px solid var(--gr);color:var(--gr);padding:12px 14px;border-radius:8px;white-space:pre-wrap;word-break:break-all}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.card b{display:block;font:700 28px ui-monospace,monospace;color:var(--cy)}
.card span{color:var(--dim);font-size:12px}
.host{background:var(--card);border:1px solid var(--line);border-radius:14px;margin:18px 0;overflow:hidden}
.host>header{padding:14px 18px;display:flex;gap:12px;align-items:center;flex-wrap:wrap;background:linear-gradient(90deg,rgba(0,229,255,.14),rgba(124,77,255,.12))}
.host h2{margin:0;font:700 18px ui-monospace,monospace;color:#fff}
.meta{padding:10px 18px;color:var(--dim);font-size:13px;border-bottom:1px solid var(--line)}
.tw{overflow-x:auto}
table{border-collapse:collapse;width:100%}
th{text-align:left;color:var(--cy);font-size:12px;padding:9px 18px;background:#0a1128}
td{padding:8px 18px;border-top:1px solid #16224d;font-family:ui-monospace,'DejaVu Sans Mono',monospace;font-size:13px;vertical-align:top}
tr:hover td{background:rgba(0,229,255,.05)}
.b{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:700}
.open,.up{background:rgba(57,255,136,.15);color:var(--gr)}
.closed,.down{background:rgba(255,77,109,.15);color:var(--rd)}
.filt{background:rgba(255,209,102,.15);color:var(--yl)}
details{border-top:1px solid #16224d}
summary{cursor:pointer;padding:10px 18px;color:#a78bff;font-weight:600}
pre{margin:0;padding:12px 18px 16px;background:#050914;color:#b9c7ee;font:12px/1.5 ui-monospace,'DejaVu Sans Mono',monospace;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
.sec{padding:12px 18px 6px;color:var(--mg);font-weight:700;font-size:13px}
.note{padding:14px 18px;color:var(--yl)}
footer{margin-top:30px;color:var(--dim);font-size:12px;text-align:center}
@media print{body{background:#fff;color:#000}.host,.card{border-color:#999}}
"""


def _badge(state):
    s = (state or "").lower()
    cls = "open" if s == "open" else "closed" if s == "closed" else "filt" if "filtered" in s else "up"
    return "<span class='b %s'>%s</span>" % (cls, html.escape(state or "?"))


def build_html(info):
    """info: cmd, raw, data (parsed XML or None), when, target, elapsed"""
    e = html.escape
    d = info.get("data")
    o = ["<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
         "<meta name='viewport' content='width=device-width,initial-scale=1'>"
         "<title>Nmap report - " + e(info.get("target", "")) + "</title><style>" + HTML_CSS +
         "</style></head><body><div class='wrap'>"]
    ver = (" &middot; Nmap " + e(d["version"])) if d and d["version"] else ""
    o.append("<h1>Nmap scan report</h1><div class='sub'>Generated " + e(info["when"]) + ver + "</div>")
    o.append("<div class='cmd'>" + e(info["cmd"]) + "</div>")
    dur = (d["elapsed"] + " s") if d and d["elapsed"] else info.get("elapsed", "-")
    cards = [("Hosts up", d["up"] if d else "-"), ("Hosts down", d["down"] if d else "-"),
             ("Open ports", count_open(d) if d else "-"), ("Duration", dur)]
    o.append("<div class='cards'>" + "".join("<div class='card'><b>%s</b><span>%s</span></div>" % (e(str(v)), k)
                                             for k, v in cards) + "</div>")
    if d and d["summary"]:
        o.append("<div class='sub'>" + e(d["summary"]) + "</div>")
    if not d:
        o.append("<div class='host'><div class='note'>Structured data is not available (the scan was "
                 "interrupted or failed). The raw console output is included below.</div></div>")
    for h in (d["hosts"] if d else []):
        title = h["ip"] or "unknown host"
        if h["names"]:
            title += " (" + h["names"][0] + ")"
        o.append("<section class='host'><header><h2>" + e(title) + "</h2>" + _badge(h["state"] or "up") + "</header>")
        meta = []
        if h["mac"]:
            meta.append("MAC " + e(h["mac"]) + (" (" + e(h["vendor"]) + ")" if h["vendor"] else ""))
        if h["uptime"]:
            meta.append("Uptime " + e(h["uptime"]))
        if h["extra"]:
            meta.append("Not shown: " + e(", ".join(h["extra"])))
        if meta:
            o.append("<div class='meta'>" + " &nbsp;|&nbsp; ".join(meta) + "</div>")
        if h["ports"]:
            o.append("<div class='tw'><table><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th>"
                     "<th>Version / info</th></tr>")
            for p in h["ports"]:
                o.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                    e(p["port"]), e(p["proto"]), _badge(p["state"]), e(p["service"]), e(p["version"])))
            o.append("</table></div>")
            sc = ["%s/%s  %s\n%s" % (p["port"], p["proto"], i, out) for p in h["ports"] for i, out in p["scripts"]]
            if sc:
                o.append("<details><summary>Script output (%d)</summary><pre>%s</pre></details>" % (
                    len(sc), e("\n\n".join(sc))))
        if h["os"]:
            o.append("<div class='sec'>OS detection</div><div class='tw'><table><tr><th>Match</th><th>Accuracy</th></tr>")
            o += ["<tr><td>%s</td><td>%s%%</td></tr>" % (e(n), e(a)) for n, a in h["os"][:6]]
            o.append("</table></div>")
        if h["trace"]:
            o.append("<div class='sec'>Traceroute</div><div class='tw'><table><tr><th>TTL</th><th>Address</th>"
                     "<th>RTT (ms)</th><th>Host</th></tr>")
            o += ["<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % tuple(e(x) for x in t) for t in h["trace"]]
            o.append("</table></div>")
        if h["scripts"]:
            o.append("<details><summary>Host scripts (%d)</summary><pre>%s</pre></details>" % (
                len(h["scripts"]), e("\n\n".join("%s\n%s" % s for s in h["scripts"]))))
        o.append("</section>")
    o.append("<section class='host'><details><summary>Raw console output</summary><pre>" +
             e(info.get("raw", "")) + "</pre></details></section>")
    o.append("<footer>Created with " + APP_NAME + " &middot; a graphical front-end for Nmap</footer>")
    o.append("</div></body></html>")
    return "".join(o)


# ───────────────────────────── custom widgets ─────────────────────────────
class BackgroundCanvas(QWidget):
    """Animated night-sky gradient with drifting glow orbs and a particle network."""

    def __init__(self):
        super().__init__()
        self.pts = [[random.random(), random.random(), random.uniform(-.0005, .0005),
                     random.uniform(-.0005, .0005)] for _ in range(58)]
        self.t = 0
        self._bg = QTimer(self, timeout=self._bg_tick)
        self._bg.start(40)

    def _bg_tick(self):
        for p in self.pts:
            p[0] = (p[0] + p[2]) % 1.0
            p[1] = (p[1] + p[3]) % 1.0
        self.t += 1
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h, t = self.width(), self.height(), self.t
        g = QLinearGradient(0, 0, w, h)
        g.setColorAt(0, QColor("#04061a"))
        g.setColorAt(.55, QColor("#0a0f2e"))
        g.setColorAt(1, QColor("#1b0733"))
        p.fillRect(self.rect(), g)
        orbs = ((.2 + .12 * math.sin(t / 140), .25 + .10 * math.cos(t / 170), (0, 229, 255)),
                (.85 + .08 * math.cos(t / 120), .80 + .10 * math.sin(t / 150), (255, 43, 214)),
                (.55 + .10 * math.sin(t / 200), .50 + .15 * math.cos(t / 130), (124, 77, 255)))
        for cx, cy, col in orbs:
            rg = QRadialGradient(cx * w, cy * h, max(w, h) * .45)
            rg.setColorAt(0, QColor(col[0], col[1], col[2], 48))
            rg.setColorAt(1, QColor(col[0], col[1], col[2], 0))
            p.fillRect(self.rect(), rg)
        pts = [(x * w, y * h) for x, y, _a, _b in self.pts]
        for i, (x, y) in enumerate(pts):
            for j in range(i + 1, len(pts)):
                dx, dy = x - pts[j][0], y - pts[j][1]
                d = dx * dx + dy * dy
                if d < 17000:
                    p.setPen(QPen(QColor(0, 229, 255, int(75 * (1 - d / 17000))), 1))
                    p.drawLine(QPointF(x, y), QPointF(pts[j][0], pts[j][1]))
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(0, 229, 255, 150))
        for x, y in pts:
            p.drawEllipse(QPointF(x, y), 1.8, 1.8)


BANNER_ART = [
    "███╗   ██╗███╗   ███╗ █████╗ ██████╗ ",
    "████╗  ██║████╗ ████║██╔══██╗██╔══██╗",
    "██╔██╗ ██║██╔████╔██║███████║██████╔╝",
    "██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ ",
    "██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     ",
    "╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ",
]


class Banner(QWidget):
    """Block-letter banner with a travelling colour sweep and a typed tagline."""
    TAG = "Network exploration and security auditing  -  graphical edition"

    def __init__(self):
        super().__init__()
        self.off, self.n, self.info = 0.0, 0.0, ""
        self.font_art = QFont(FONT_MONO, 14)
        self.font_art.setStyleHint(QFont.Monospace)
        self.font_art.setBold(True)
        self.fm = QFontMetrics(self.font_art)
        self.setFixedHeight(len(BANNER_ART) * self.fm.height() + 58)
        QTimer(self, timeout=self._tick).start(40)

    def _tick(self):
        self.off = (self.off + 5) % 420
        self.n += 0.55
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.TextAntialiasing)
        p.setFont(self.font_art)
        lh, asc = self.fm.height(), self.fm.ascent()
        grad = QLinearGradient(self.off, 0, self.off + 420, 0)
        grad.setSpread(QLinearGradient.RepeatSpread)
        for pos, c in ((0, CYAN), (.33, VIO), (.66, MAG), (1, CYAN)):
            grad.setColorAt(pos, QColor(c))
        for i, line in enumerate(BANNER_ART):
            y = 6 + asc + i * lh
            p.setPen(QColor(0, 229, 255, 38))                      # soft glow
            p.drawText(5, y + 1, line)
            p.drawText(7, y - 1, line)
            p.setPen(QPen(QBrush(grad), 1))
            p.drawText(6, y, line)
        f = QFont(FONT_UI, 11)
        p.setFont(f)
        ty = 6 + len(BANNER_ART) * lh + 22
        shown = self.TAG[:int(self.n)]
        cursor = "▌" if int(self.n / 4) % 2 == 0 and int(self.n) < len(self.TAG) + 40 else ""
        p.setPen(QColor("#9fb4ff"))
        p.drawText(8, ty, shown + cursor)
        if self.info:
            p.setPen(QColor(GRN))
            p.drawText(8, ty + 20, self.info)


class Radar(QWidget):
    """Little radar: idles slowly, spins up and paints blips while a scan runs."""

    def __init__(self):
        super().__init__()
        self.setFixedSize(150, 150)
        self.ang, self.speed, self.active, self.blips = 0.0, 1.4, False, []
        QTimer(self, timeout=self._tick).start(33)

    def set_active(self, on):
        self.active = on

    def _tick(self):
        self.speed += ((7.0 if self.active else 1.4) - self.speed) * 0.08
        self.ang = (self.ang - self.speed) % 360
        if self.active and random.random() < 0.14:
            self.blips.append([self.ang, random.uniform(.2, .95), 1.0])
        for b in self.blips:
            b[2] -= 0.012
        self.blips = [b for b in self.blips if b[2] > 0]
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        c = QPointF(self.width() / 2, self.height() / 2)
        R = self.width() / 2 - 6
        p.setBrush(QColor(2, 10, 24, 190))
        p.setPen(QPen(QColor(0, 229, 255, 120), 1.4))
        p.drawEllipse(c, R, R)
        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(QColor(0, 229, 255, 45), 1))
        for k in (.33, .66):
            p.drawEllipse(c, R * k, R * k)
        p.drawLine(QPointF(c.x() - R, c.y()), QPointF(c.x() + R, c.y()))
        p.drawLine(QPointF(c.x(), c.y() - R), QPointF(c.x(), c.y() + R))
        g = QConicalGradient(c, self.ang)
        g.setColorAt(0, QColor(57, 255, 136, 175))
        g.setColorAt(.14, QColor(57, 255, 136, 0))
        g.setColorAt(1, QColor(57, 255, 136, 0))
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(g))
        p.drawEllipse(c, R, R)
        for a, r, life in self.blips:
            x = c.x() + math.cos(math.radians(a)) * R * r
            y = c.y() - math.sin(math.radians(a)) * R * r
            p.setBrush(QColor(255, 43, 214, int(255 * life)))
            p.drawEllipse(QPointF(x, y), 3, 3)


class NeonProgress(QWidget):
    """Gradient progress bar with a moving shimmer; bounces when progress is unknown."""

    def __init__(self):
        super().__init__()
        self.setFixedHeight(32)
        self.v, self.t, self.ph, self.indet, self.label = 0.0, 0.0, 0.0, False, ""
        QTimer(self, timeout=self._tick).start(25)

    def set_target(self, pct):
        self.indet = False
        self.t = max(0.0, min(100.0, pct))

    def reset(self):
        self.v = self.t = 0.0
        self.indet, self.label = False, ""

    def _tick(self):
        self.v += (self.t - self.v) * 0.12
        self.ph = (self.ph + 0.02) % 1.0
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(1, 1, self.width() - 2, self.height() - 2)
        path = QPainterPath()
        path.addRoundedRect(r, r.height() / 2, r.height() / 2)
        p.fillPath(path, QColor(3, 6, 20, 225))
        p.setPen(QPen(QColor(0, 229, 255, 95), 1))
        p.drawPath(path)
        p.setClipPath(path)
        if self.indet:
            w = r.width() * .3
            fr = QRectF(r.left() + (r.width() + w) * self.ph - w, r.top(), w, r.height())
        else:
            fr = QRectF(r.left(), r.top(), r.width() * self.v / 100.0, r.height())
        if fr.width() > 1:
            g = QLinearGradient(fr.left(), 0, fr.right(), 0)
            g.setColorAt(0, QColor(CYAN))
            g.setColorAt(.6, QColor(VIO))
            g.setColorAt(1, QColor(MAG))
            p.fillRect(fr, g)
            sx = r.left() + (r.width() + 140) * self.ph - 140
            sh = QLinearGradient(sx, 0, sx + 140, 0)
            sh.setColorAt(0, QColor(255, 255, 255, 0))
            sh.setColorAt(.5, QColor(255, 255, 255, 95))
            sh.setColorAt(1, QColor(255, 255, 255, 0))
            p.save()
            p.setClipRect(fr, Qt.IntersectClip)
            p.fillRect(r, sh)
            p.restore()
        p.setClipping(False)
        f = QFont(FONT_MONO, 10)
        f.setBold(True)
        p.setFont(f)
        txt = (self.label + "   " if self.label else "") + ("" if self.indet else "%.0f%%" % self.v)
        p.setPen(QColor(0, 0, 0, 170))
        p.drawText(self.rect().translated(1, 1), Qt.AlignCenter, txt)
        p.setPen(QColor("white"))
        p.drawText(self.rect(), Qt.AlignCenter, txt)


class StatCard(QFrame):
    """Small stat tile whose number counts up smoothly."""

    def __init__(self, title, color=CYAN):
        super().__init__()
        self.setObjectName("card")
        v = QVBoxLayout(self)
        v.setContentsMargins(14, 8, 14, 8)
        v.setSpacing(0)
        t = QLabel(title)
        t.setObjectName("cardTitle")
        self.val = QLabel("0")
        self.val.setObjectName("cardValue")
        self.val.setStyleSheet("color:%s;" % color)
        v.addWidget(t)
        v.addWidget(self.val)
        self.cur = 0
        self.anim = QVariantAnimation(self)
        self.anim.setDuration(700)
        self.anim.setEasingCurve(QEasingCurve.OutCubic)
        self.anim.valueChanged.connect(lambda x: self.val.setText(str(int(x))))

    def count_to(self, n):
        self.anim.stop()
        self.anim.setStartValue(int(self.cur))
        self.anim.setEndValue(int(n))
        self.cur = int(n)
        self.anim.start()

    def text(self, s):
        self.anim.stop()
        self.val.setText(s)


class OutHL(QSyntaxHighlighter):
    """Colours Nmap console output."""

    def __init__(self, doc):
        super().__init__(doc)

        def fmt(color, bold=False, italic=False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Bold)
            f.setFontItalic(italic)
            return f
        self.rules = [
            (re.compile(r"^\|.*$"), fmt("#b388ff")),
            (re.compile(r"^(Starting Nmap|Nmap done|Initiating|Completed|Discovered|NSE:|Read data files).*$"), fmt("#8fa3d6")),
            (re.compile(r"^(Host is up|MAC Address|OS details|Running|Device type|Service Info|Network Distance|"
                        r"Not shown|OS CPE|Aggressive OS guesses|Uptime guess|TRACEROUTE|HOP|PORT|Warning|WARNING|"
                        r"QUITTING|Note).*$"), fmt("#9fd8ff")),
            (re.compile(r"^Nmap scan report for .*$"), fmt(MAG, True)),
            (re.compile(r"\b\d{1,5}/(?:tcp|udp|sctp)\b"), fmt(CYAN, True)),
            (re.compile(r"\bfiltered\b|\bopen\|filtered\b|\bclosed\|filtered\b"), fmt(YEL)),
            (re.compile(r"\bclosed\b"), fmt(RED)),
            (re.compile(r"\bopen\b"), fmt(GRN, True)),
            (re.compile(r"^\$ .*$"), fmt(GRN, False, True)),
        ]

    def highlightBlock(self, text):
        for rx, f in self.rules:
            for m in rx.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), f)


class OptRow(QWidget):
    """One Nmap option: tick-box + flag name + description (+ value input)."""
    changed = pyqtSignal()

    def __init__(self, key, kind, label, hint="", choices=None):
        super().__init__()
        self.key, self.kind, self.cb, self.inp = key, kind, None, None
        lay = QHBoxLayout(self)
        lay.setContentsMargins(4, 3, 4, 3)
        lay.setSpacing(8)
        emit = lambda *_: self.changed.emit()
        if kind == "sel":
            d = QLabel(label)
            d.setObjectName("desc")
            lay.addWidget(d, 1)
            self.inp = QComboBox()
            self.inp.setMinimumWidth(210)
            self.inp.addItem("- default -", "")
            for text, val in choices:
                self.inp.addItem(text, val)
            self.inp.currentIndexChanged.connect(emit)
            lay.addWidget(self.inp)
            return
        self.cb = QCheckBox(key)
        self.cb.setObjectName("flagcb")
        self.cb.setMinimumWidth(176)
        self.cb.setToolTip("nmap " + key + ("  -  " + label))
        self.cb.toggled.connect(emit)
        lay.addWidget(self.cb)
        d = QLabel(label)
        d.setObjectName("desc")
        d.setWordWrap(True)
        lay.addWidget(d, 1)
        if kind != "flag":
            if choices:
                self.inp = QComboBox()
                for text, val in choices:
                    self.inp.addItem(text, val)
                self.inp.currentIndexChanged.connect(emit)
            else:
                self.inp = QLineEdit()
                self.inp.setPlaceholderText(hint)
                self.inp.textChanged.connect(emit)
            self.inp.setFixedWidth(170)
            self.inp.setEnabled(False)
            self.cb.toggled.connect(self.inp.setEnabled)
            lay.addWidget(self.inp)
            if kind == "file":
                b = QPushButton("...")
                b.setObjectName("mini")
                b.setFixedWidth(34)
                b.setEnabled(False)
                b.clicked.connect(self._browse)
                self.cb.toggled.connect(b.setEnabled)
                lay.addWidget(b)

    def _browse(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select file")
        if f:
            self.inp.setText(f)

    def val(self):
        if isinstance(self.inp, QComboBox):
            return str(self.inp.currentData() or "")
        return self.inp.text().strip() if self.inp is not None else ""

    def args(self):
        if self.kind == "sel":
            v = self.val()
            return [v] if v else []
        if not self.cb.isChecked():
            return []
        if self.kind == "flag":
            return [self.key]
        v = self.val()
        if self.kind == "att":
            return [self.key + v]
        return [self.key, v] if v else []

    def set(self, value):
        if self.kind == "sel":
            i = self.inp.findData(value)
            self.inp.setCurrentIndex(max(i, 0))
            return
        self.cb.setChecked(True)
        if self.kind != "flag" and value not in (True, None):
            if isinstance(self.inp, QComboBox):
                self.inp.setCurrentIndex(max(self.inp.findData(str(value)), 0))
            else:
                self.inp.setText(str(value))

    def reset(self):
        if self.kind == "sel":
            self.inp.setCurrentIndex(0)
            return
        self.cb.setChecked(False)
        if isinstance(self.inp, QLineEdit):
            self.inp.clear()
        elif isinstance(self.inp, QComboBox):
            self.inp.setCurrentIndex(0)


class ChipGroup(QWidget):
    """Exclusive chip buttons (used for the TCP scan technique)."""
    changed = pyqtSignal()

    def __init__(self, key, items, cols=4):
        super().__init__()
        self.key, self.btns = key, {}
        grid = QGridLayout(self)
        grid.setContentsMargins(2, 4, 2, 4)
        grid.setSpacing(6)
        self.grp = QButtonGroup(self)
        self.grp.setExclusive(True)
        for i, (flag, name, tip) in enumerate(items):
            b = QPushButton("%s\n%s" % (flag or "-", name))
            b.setObjectName("chip")
            b.setCheckable(True)
            b.setToolTip(tip)
            self.grp.addButton(b)
            self.btns[flag] = b
            grid.addWidget(b, i // cols, i % cols)
        self.btns[""].setChecked(True)
        self.grp.buttonClicked.connect(lambda *_: self.changed.emit())

    def args(self):
        for flag, b in self.btns.items():
            if b.isChecked() and flag:
                return [flag]
        return []

    def set(self, flag):
        self.btns.get(flag, self.btns[""]).setChecked(True)
        self.changed.emit()

    def reset(self):
        self.btns[""].setChecked(True)


# ───────────────────────────── main window ─────────────────────────────
RX_PCT = re.compile(r"^(.*?) Timing: About ([\d.]+)% done(?:; ETC: [^()]*\(([\d:]+) remaining\))?")


def state_color(s):
    s = (s or "").lower()
    return GRN if s == "open" else RED if s == "closed" else YEL if "filtered" in s else DIM


def nmap_version():
    try:
        out = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"Nmap version (\S+)", out)
        return m.group(1) if m else ""
    except Exception:
        return ""


class Glass(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("glass")


class NmapGUI(BackgroundCanvas):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NmapGUI - Network Mapper")
        self.resize(1420, 920)
        self.setMinimumSize(1120, 740)
        self.setStyleSheet(build_qss())
        self.rows, self.cat_btns = {}, {}
        self.proc = QProcess(self)
        self.proc.setProcessChannelMode(QProcess.MergedChannels)
        self.proc.readyReadStandardOutput.connect(self.on_out)
        self.proc.finished.connect(self.on_done)
        self.proc.errorOccurred.connect(self.on_err)
        self.buf, self.raw, self.last, self.xml_path = "", [], None, None
        self.tool_mode = self.stopped = False
        self.open_live, self.cmd_text, self.target_text = 0, "", ""
        self.clock = QElapsedTimer()
        self.sec = QTimer(self, timeout=self.on_sec)
        self._build()
        self.refresh_cmd()
        self.write("$ nmap --help   (Tools menu)\n"
                   "Type a target, pick a profile or tick any options on the left, then press Start scan.\n"
                   "The HTML report is only written when you press 'Save HTML report' (default folder: reports/).\n", keep=False)

    # ---------- UI construction ----------
    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 10, 16, 12)
        root.setSpacing(10)

        head = QHBoxLayout()
        self.banner, self.radar = Banner(), Radar()
        ver, is_root = nmap_version(), (hasattr(os, "geteuid") and os.geteuid() == 0)
        self.banner.info = ("nmap %s detected" % ver if ver else "nmap not found") + \
                           ("   |   running as root" if is_root else "   |   not root: raw-socket scans limited")
        head.addWidget(self.banner, 1)
        head.addWidget(self.radar)
        root.addLayout(head)

        bar = Glass()
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(14, 12, 14, 12)
        bl.setSpacing(10)
        self.target = QLineEdit()
        self.target.setObjectName("target")
        self.target.setPlaceholderText("Target(s):  scanme.nmap.org    192.168.1.0/24    10.0.0.1-50")
        self.target.returnPressed.connect(self.start_scan)
        self.target.textChanged.connect(self.refresh_cmd)
        self.profile = QComboBox()
        self.profile.addItems(list(PROFILES))
        self.profile.setMinimumWidth(240)
        self.profile.activated[str].connect(self.apply_profile)
        self.btn_start = QPushButton("Start scan")
        self.btn_start.setObjectName("start")
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setObjectName("stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_tools = QPushButton("Tools")
        menu = QMenu(self)
        menu.addAction("Nmap version  (-V)", lambda: self.run_tool(["-V"]))
        menu.addAction("Nmap help  (-h)", lambda: self.run_tool(["-h"]))
        menu.addAction("Interfaces and routes  (--iflist)", lambda: self.run_tool(["--iflist"]))
        menu.addAction("Update NSE script database", lambda: self.run_tool(["--script-updatedb"]))
        menu.addAction("NSE script help ...", self.script_help)
        menu.addSeparator()
        menu.addAction("Clear console", lambda: self.console.clear())
        menu.addAction("Reset all options", self.reset_opts)
        self.btn_tools.setMenu(menu)
        bl.addWidget(self.target, 1)
        bl.addWidget(QLabel("Profile"))
        bl.addWidget(self.profile)
        bl.addWidget(self.btn_start)
        bl.addWidget(self.btn_stop)
        bl.addWidget(self.btn_tools)
        root.addWidget(bar)

        split = QSplitter(Qt.Horizontal)
        split.setChildrenCollapsible(False)
        left = Glass()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(10, 10, 10, 10)
        self.tcp = ChipGroup("tcp", TCP_MODES)
        self.tcp.changed.connect(self.refresh_cmd)
        self.opt_tabs = QTabWidget()
        self.opt_tabs.setUsesScrollButtons(True)
        self.opt_tabs.setElideMode(Qt.ElideNone)
        for name, items in OPT_TABS:
            self.opt_tabs.addTab(self._tab(items), name)
        ll.addWidget(self.opt_tabs)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(10)
        cards = QHBoxLayout()
        cards.setSpacing(10)
        self.c_hosts = StatCard("Hosts up", CYAN)
        self.c_open = StatCard("Open ports", GRN)
        self.c_time = StatCard("Elapsed", MAG)
        self.c_time.text("0.0 s")
        for c in (self.c_hosts, self.c_open, self.c_time):
            cards.addWidget(c)
        rl.addLayout(cards)
        out = Glass()
        ol = QVBoxLayout(out)
        ol.setContentsMargins(10, 10, 10, 10)
        self.out_tabs = QTabWidget()
        self.console = QPlainTextEdit()
        self.console.setObjectName("console")
        self.console.setReadOnly(True)
        self.console.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.console.setMaximumBlockCount(30000)
        f = QFont(FONT_MONO, 10)
        f.setStyleHint(QFont.Monospace)
        self.console.setFont(f)
        self.hl = OutHL(self.console.document())
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Host / port", "Proto", "State", "Service", "Version / info"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setColumnWidth(0, 230)
        self.tree.setColumnWidth(1, 60)
        self.tree.setColumnWidth(2, 110)
        self.tree.setColumnWidth(3, 130)
        self.out_tabs.addTab(self.console, "Console")
        self.out_tabs.addTab(self.tree, "Results")
        ol.addWidget(self.out_tabs)
        rl.addWidget(out, 1)
        split.addWidget(left)
        split.addWidget(right)
        split.setSizes([640, 760])
        split.setStretchFactor(1, 1)
        root.addWidget(split, 1)

        cmdp = Glass()
        cl = QGridLayout(cmdp)
        cl.setContentsMargins(14, 10, 14, 10)
        cl.setHorizontalSpacing(10)
        cl.setVerticalSpacing(6)
        self.extra = QLineEdit()
        self.extra.setObjectName("extra")
        self.extra.setPlaceholderText("Any other Nmap flag, typed exactly as on the command line, e.g.  --max-retries 2")
        self.extra.textChanged.connect(self.refresh_cmd)
        self.cmd = QLineEdit()
        self.cmd.setObjectName("cmd")
        self.cmd.setReadOnly(True)
        cp = QPushButton("Copy")
        cp.clicked.connect(lambda: (QApplication.clipboard().setText(self.cmd.text()), self.toast("Command copied", CYAN)))
        cl.addWidget(QLabel("Extra flags"), 0, 0)
        cl.addWidget(self.extra, 0, 1, 1, 2)
        cl.addWidget(QLabel("Command"), 1, 0)
        cl.addWidget(self.cmd, 1, 1)
        cl.addWidget(cp, 1, 2)
        cl.setColumnStretch(1, 1)
        root.addWidget(cmdp)

        pr = QHBoxLayout()
        pr.setSpacing(10)
        self.prog = NeonProgress()
        pr.addWidget(self.prog, 1)
        self.btn_save = QPushButton("Save HTML report")
        self.btn_save.setObjectName("save")
        self.btn_txt, self.btn_xml = QPushButton("Save .txt"), QPushButton("Save .xml")
        self.btn_save.clicked.connect(lambda: self._save("html"))
        self.btn_txt.clicked.connect(lambda: self._save("txt"))
        self.btn_xml.clicked.connect(lambda: self._save("xml"))
        for b in (self.btn_save, self.btn_txt, self.btn_xml):
            b.setEnabled(False)
            pr.addWidget(b)
        root.addLayout(pr)

        sr = QHBoxLayout()
        self.dot, self.status = QLabel("●"), QLabel("")
        sr.addWidget(self.dot)
        sr.addWidget(self.status, 1)
        warn = QLabel("" if is_root else "Not root: SYN, UDP, OS and ARP scans need  sudo -E python3 nmap_gui.py")
        warn.setStyleSheet("color:%s;" % YEL)
        sr.addWidget(warn)
        root.addLayout(sr)
        self.set_status("Ready", GRN)

        self.glow_start = self._pulse(self.btn_start, CYAN)
        self.glow_save = self._pulse(self.btn_save, MAG)
        self._glow(self.glow_start, True)
        for b in self.findChildren(QPushButton):
            b.setCursor(Qt.PointingHandCursor)

    def _tab(self, items):
        inner = QWidget()
        v = QVBoxLayout(inner)
        v.setContentsMargins(8, 6, 8, 14)
        v.setSpacing(1)
        for it in items:
            if it == "@tcp":
                v.addWidget(self.tcp)
            elif it == "@cats":
                v.addWidget(self._cats())
            elif isinstance(it, str):
                lb = QLabel(it)
                lb.setObjectName("section")
                v.addWidget(lb)
            else:
                r = OptRow(*it)
                r.changed.connect(self.refresh_cmd)
                self.rows[r.key] = r
                v.addWidget(r)
        v.addStretch(1)
        sc = QScrollArea()
        sc.setWidgetResizable(True)
        sc.setWidget(inner)
        inner.setAutoFillBackground(False)
        sc.viewport().setAutoFillBackground(False)
        return sc

    def _cats(self):
        w = QWidget()
        g = QGridLayout(w)
        g.setContentsMargins(2, 2, 2, 6)
        g.setSpacing(6)
        for i, c in enumerate(NSE_CATS):
            b = QPushButton(c)
            b.setObjectName("cat")
            b.setCheckable(True)
            b.toggled.connect(lambda on, c=c: self._cat_toggle(c, on))
            self.cat_btns[c] = b
            g.addWidget(b, i // 5, i % 5)
        return w

    def _cat_toggle(self, cat, on):
        r = self.rows["--script"]
        parts = [x for x in r.val().split(",") if x]
        if on and cat not in parts:
            parts.append(cat)
        if not on and cat in parts:
            parts.remove(cat)
        r.set(",".join(parts)) if parts else r.reset()

    def _pulse(self, btn, color):
        fx = QGraphicsDropShadowEffect(btn)
        fx.setOffset(0, 0)
        fx.setColor(QColor(color))
        fx.setBlurRadius(0)
        btn.setGraphicsEffect(fx)
        a = QPropertyAnimation(fx, b"blurRadius", self)
        a.setDuration(1700)
        a.setStartValue(6)
        a.setKeyValueAt(.5, 34)
        a.setEndValue(6)
        a.setLoopCount(-1)
        return fx, a

    @staticmethod
    def _glow(pair, on):
        fx, a = pair
        if on:
            a.start()
        else:
            a.stop()
            fx.setBlurRadius(0)

    # ---------- command building ----------
    def full_args(self):
        a = self.tcp.args()
        for r in self.rows.values():
            a += r.args()
        for field in (self.extra, self.target):
            t = field.text()
            try:
                a += shlex.split(t)
            except ValueError:
                a += t.split()
        return a

    def refresh_cmd(self, *_):
        if hasattr(self, "cmd"):
            self.cmd.setText("nmap " + " ".join(shlex.quote(x) for x in self.full_args()))

    def reset_opts(self):
        for r in self.rows.values():
            r.reset()
        self.tcp.reset()
        for b in self.cat_btns.values():
            b.blockSignals(True)
            b.setChecked(False)
            b.blockSignals(False)
        self.refresh_cmd()

    def apply_profile(self, name):
        if name not in PROFILES or name.startswith("-"):
            return
        self.reset_opts()
        for k, v in PROFILES[name].items():
            if k == "tcp":
                self.tcp.set(v)
            else:
                self.rows[k].set(v)
        self.refresh_cmd()

    # ---------- running nmap ----------
    def start_scan(self):
        if self.proc.state() != QProcess.NotRunning:
            return
        args = self.full_args()
        if not (self.target.text().strip() or "-iL" in args or "-iR" in args):
            self.target.setFocus()
            self.toast("Enter a target first: host, IP, range or CIDR", YEL)
            return
        self._clean_tmp()
        fd, self.xml_path = tempfile.mkstemp(prefix="nmapgui_", suffix=".xml")
        os.close(fd)
        run = list(args)
        if "--stats-every" not in run:
            run += ["--stats-every", "1s"]
        run += ["-oX", self.xml_path]          # structured data for the report; nothing is saved to disk for you
        self.cmd_text = "nmap " + " ".join(shlex.quote(x) for x in args)
        self.target_text = self.target.text().strip() or "targets from file"
        self._launch(run, self.cmd_text, tool=False)

    def run_tool(self, args):
        if self.proc.state() != QProcess.NotRunning:
            return self.toast("A scan is still running", YEL)
        self._launch(args, "nmap " + " ".join(args), tool=True)

    def script_help(self):
        t, ok = QInputDialog.getText(self, "NSE script help", "Script name, category or wildcard (e.g. http-*):")
        if ok and t.strip():
            self.run_tool(["--script-help", t.strip()])

    def _launch(self, run, shown, tool):
        self.tool_mode, self.stopped, self.buf, self.raw, self.open_live = tool, False, "", [], 0
        self.console.clear()
        self.out_tabs.setCurrentIndex(0)
        self.write("$ " + shown + "\n", keep=False)
        if not tool:
            self.tree.clear()
            self.last = None
            self.c_hosts.count_to(0)
            self.c_open.count_to(0)
        self.c_time.text("0.0 s")
        self.prog.reset()
        self.prog.indet, self.prog.label = True, "Starting"
        self.set_running(True)
        self.clock.start()
        self.sec.start(200)
        self.set_status("Running ..." if tool else "Scanning ...", CYAN)
        self.proc.start("nmap", run)

    def stop_scan(self):
        if self.proc.state() == QProcess.NotRunning:
            return
        self.stopped = True
        self.set_status("Stopping ...", YEL)
        self.proc.terminate()
        QTimer.singleShot(2500, lambda: self.proc.state() != QProcess.NotRunning and self.proc.kill())

    def set_running(self, on):
        self.btn_start.setEnabled(not on)
        self.btn_stop.setEnabled(on)
        self.radar.set_active(on)
        self._glow(self.glow_start, not on)
        if on:
            self._enable_save(False)

    def _enable_save(self, on):
        for b in (self.btn_save, self.btn_txt, self.btn_xml):
            b.setEnabled(on)
        self._glow(self.glow_save, on)

    def on_out(self):
        self.buf += bytes(self.proc.readAllStandardOutput()).decode("utf-8", "replace")
        *lines, self.buf = self.buf.split("\n")
        keep = [ln.rstrip("\r") for ln in lines if not self.parse_progress(ln.rstrip("\r"))]
        if keep:
            self.write("\n".join(keep) + "\n")

    def parse_progress(self, ln):
        m = RX_PCT.match(ln)
        if m:
            self.prog.set_target(float(m.group(2)))
            self.prog.label = m.group(1).strip()
            self.set_status(m.group(1).strip() + (" - about %s left" % m.group(3) if m.group(3) else ""), CYAN)
            return True
        if ln.startswith("Stats: "):
            return True
        if ln.startswith("Discovered open port"):
            self.open_live += 1
            self.c_open.count_to(self.open_live)
        return False

    def write(self, text, keep=True):
        if keep:
            self.raw.append(text)
        self.console.moveCursor(QTextCursor.End)
        self.console.insertPlainText(text)
        self.console.moveCursor(QTextCursor.End)

    def on_sec(self):
        self.c_time.text("%.1f s" % (self.clock.elapsed() / 1000.0))

    def on_done(self, code, _status):
        self.sec.stop()
        if self.buf.strip():
            self.write(self.buf + "\n")
        self.buf = ""
        secs = self.clock.elapsed() / 1000.0
        self.c_time.text("%.1f s" % secs)
        self.set_running(False)
        if self.tool_mode:
            self.prog.reset()
            self.set_status("Finished", DIM)
            self._enable_save(self.last is not None)
            return
        ok = code == 0 or self.stopped
        data = None
        try:
            if self.xml_path and os.path.getsize(self.xml_path) > 0:
                data = parse_xml(self.xml_path)
        except Exception:
            data = None
        if ok:
            self.last = {"cmd": self.cmd_text, "raw": "".join(self.raw), "data": data,
                         "when": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                         "target": self.target_text, "elapsed": "%.1f s" % secs}
            self._enable_save(True)
        if data:
            self.fill_results(data)
            if data["hosts"]:
                self.out_tabs.setCurrentIndex(1)
        self.prog.indet = False
        if self.stopped:
            self.prog.label = "Stopped"
            self.set_status("Scan stopped. The partial output can still be saved.", YEL)
        elif code != 0:
            self.prog.label = "Failed"
            self.set_status("Nmap exited with code %d. See the console for details." % code, RED)
        else:
            self.prog.set_target(100)
            self.prog.label = "Complete"
            self.set_status("Scan complete in %.1f s" % secs, GRN)
            self.toast("Scan complete. Press 'Save HTML report' to export it.", GRN)

    def on_err(self, err):
        if err == QProcess.FailedToStart:
            self.sec.stop()
            self.set_running(False)
            self.prog.reset()
            self.set_status("Could not start nmap", RED)
            QMessageBox.critical(self, "Cannot start nmap", "Nmap was not found.\n\nInstall it with:  sudo apt install nmap")

    # ---------- results ----------
    def fill_results(self, d):
        t = self.tree
        t.clear()
        bold = QFont(FONT_MONO, 10)
        bold.setBold(True)
        for h in d["hosts"]:
            name = h["ip"] + ("  (%s)" % h["names"][0] if h["names"] else "")
            extra = "   ".join(x for x in ("MAC " + h["mac"] if h["mac"] else "", "[%s]" % h["vendor"] if h["vendor"] else "") if x)
            hi = QTreeWidgetItem([name, "", (h["state"] or "up").upper(), "", extra])
            hi.setFont(0, bold)
            hi.setForeground(0, QBrush(QColor(MAG)))
            hi.setForeground(2, QBrush(QColor(GRN if h["state"] != "down" else RED)))
            t.addTopLevelItem(hi)
            for p in h["ports"]:
                pi = QTreeWidgetItem(hi, [p["port"], p["proto"], p["state"], p["service"], p["version"]])
                pi.setForeground(0, QBrush(QColor(CYAN)))
                pi.setForeground(2, QBrush(QColor(state_color(p["state"]))))
                for sid, so in p["scripts"]:
                    si = QTreeWidgetItem(pi, ["  > " + sid, "", "", "", " ".join(so.split())[:220]])
                    si.setForeground(0, QBrush(QColor("#b388ff")))
                    si.setToolTip(4, so)
            if h["extra"]:
                ni = QTreeWidgetItem(hi, ["Not shown: " + ", ".join(h["extra"])])
                ni.setForeground(0, QBrush(QColor(DIM)))
            for n, acc in h["os"][:5]:
                oi = QTreeWidgetItem(hi, ["OS guess", "", acc + "%", "", n])
                oi.setForeground(0, QBrush(QColor(YEL)))
            if h["trace"]:
                ti = QTreeWidgetItem(hi, ["Traceroute"])
                ti.setForeground(0, QBrush(QColor(YEL)))
                for ttl, ip, rtt, hn in h["trace"]:
                    QTreeWidgetItem(ti, ["hop " + ttl, "", rtt + " ms", "", ip + (" (%s)" % hn if hn else "")])
            for sid, so in h["scripts"]:
                si = QTreeWidgetItem(hi, ["  > " + sid, "", "", "", " ".join(so.split())[:220]])
                si.setForeground(0, QBrush(QColor("#b388ff")))
                si.setToolTip(4, so)
            hi.setExpanded(True)
        self.c_hosts.count_to(d["up"])
        self.c_open.count_to(count_open(d))

    # ---------- exporting (only when the user asks) ----------
    def _save(self, kind):
        if not self.last:
            return
        title, ext = {"html": ("HTML report", "html"), "txt": ("console output", "txt"),
                      "xml": ("Nmap XML", "xml")}[kind]
        if kind == "xml" and not (self.xml_path and os.path.exists(self.xml_path) and os.path.getsize(self.xml_path)):
            return self.toast("No XML available for this scan", YEL)
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        folder = REPORT_DIR
        try:
            os.makedirs(folder, exist_ok=True)
        except OSError:
            folder = os.path.expanduser("~")
        path, _ = QFileDialog.getSaveFileName(self, "Save " + title, os.path.join(folder, "nmap_%s.%s" % (stamp, ext)),
                                              "%s (*.%s)" % (title, ext))
        if not path:
            return
        if not path.lower().endswith("." + ext):
            path += "." + ext
        try:
            if kind == "html":
                with open(path, "w", encoding="utf-8") as f:
                    f.write(build_html(self.last))
            elif kind == "txt":
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.last["cmd"] + "\n\n" + self.last["raw"])
            else:
                shutil.copy(self.xml_path, path)
        except OSError as ex:
            return self.toast("Could not save: %s" % ex, RED)
        self._glow(self.glow_save, False)
        self.toast("Saved  " + path, GRN)

    # ---------- small helpers ----------
    def set_status(self, msg, color=CYAN):
        self.dot.setStyleSheet("color:%s;font-size:16px;" % color)
        self.status.setText(msg)

    def toast(self, msg, color=GRN):
        lb = QLabel(msg, self)
        lb.setStyleSheet("background:rgba(8,12,34,240);color:%s;border:1px solid %s;border-radius:10px;"
                         "padding:10px 18px;font-weight:bold;" % (color, color))
        lb.adjustSize()
        lb.move(max(0, (self.width() - lb.width()) // 2), self.height() - lb.height() - 110)
        lb.show()
        lb.raise_()
        fx = QGraphicsOpacityEffect(lb)
        lb.setGraphicsEffect(fx)
        a = QPropertyAnimation(fx, b"opacity", lb)
        a.setDuration(3400)
        for k, v in ((0, 0), (.08, 1), (.85, 1), (1, 0)):
            a.setKeyValueAt(k, v)
        a.finished.connect(lb.deleteLater)
        a.start()

    def _clean_tmp(self):
        if self.xml_path and os.path.exists(self.xml_path):
            try:
                os.remove(self.xml_path)
            except OSError:
                pass

    def closeEvent(self, ev):
        if self.proc.state() != QProcess.NotRunning:
            self.proc.kill()
            self.proc.waitForFinished(1500)
        self._clean_tmp()
        super().closeEvent(ev)


def main():
    global FONT_MONO, FONT_UI
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    fams = set(QFontDatabase().families())
    pick = lambda cands, default: next((c for c in cands if c in fams), default)
    FONT_MONO = pick(["JetBrains Mono", "Hack", "Fira Code", "Source Code Pro", "DejaVu Sans Mono",
                      "Liberation Mono"], "monospace")
    FONT_UI = pick(["Rajdhani", "Exo 2", "Ubuntu", "Noto Sans", "Cantarell", "DejaVu Sans"], "sans-serif")
    app.setFont(QFont(FONT_UI, 10))
    pal = QPalette()
    for role, col in ((QPalette.Window, "#0b1230"), (QPalette.WindowText, TXT), (QPalette.Base, "#060a1e"),
                      (QPalette.AlternateBase, "#0b1230"), (QPalette.Text, TXT), (QPalette.Button, "#0b1230"),
                      (QPalette.ButtonText, TXT), (QPalette.Highlight, VIO), (QPalette.HighlightedText, "#ffffff"),
                      (QPalette.ToolTipBase, "#0b1230"), (QPalette.ToolTipText, TXT)):
        pal.setColor(role, QColor(col))
    app.setPalette(pal)
    if not shutil.which("nmap"):
        QMessageBox.critical(None, "Nmap not found", "Install it with:  sudo apt install nmap")
        return 1
    w = NmapGUI()
    w.setWindowOpacity(0.0)
    w.show()
    fade = QPropertyAnimation(w, b"windowOpacity", w)
    fade.setDuration(900)
    fade.setStartValue(0.0)
    fade.setEndValue(1.0)
    fade.setEasingCurve(QEasingCurve.OutCubic)
    fade.start()
    w._fade = fade
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
