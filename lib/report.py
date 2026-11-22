#!/usr/bin/env python3
"""XamlTech Nmap Toolkit - report engine (stdlib only).

Subcommands
  report     parse Nmap XML (one or many stages) -> report.json/csv/md/html
  dashboard  render a colored terminal summary from report.json
  diff       compare two report.json files (or run dirs)
  history    table of previous runs in a results directory
  hosts-up / hosts-open / ports   helpers for multi-stage workflows
  classify   internal | external | unknown for a set of targets
  scope      verify targets against an authorized scope file

All text taken from scanned hosts (banners, script output) is untrusted: it is
HTML-escaped, CSV formula-neutralised and Markdown-escaped before being written.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import html
import ipaddress
import itertools
import json
import os
import re
import shutil
import socket
import sys
import threading
import xml.etree.ElementTree as ET
from collections import Counter, OrderedDict

VERSION = "2.1.1"
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
# Odoo majors older than this are reported as likely out of support (edit to taste).
ODOO_MIN_SUPPORTED = 17


# --------------------------------------------------------------------------- #
# XML parsing
# --------------------------------------------------------------------------- #
def load_xml(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    if b"<!ENTITY" in raw:
        raise ValueError(f"{path}: XML entities are not allowed")
    try:
        return ET.fromstring(raw)
    except ET.ParseError:
        # interrupted scans leave an unterminated document; try a best-effort close
        fixed = raw + b"</host></nmaprun>" if b"</nmaprun>" not in raw else raw
        try:
            return ET.fromstring(fixed)
        except ET.ParseError as exc:
            raise ValueError(f"{path}: not valid Nmap XML ({exc})") from exc


def _int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def parse_script(el):
    return {"id": el.get("id", ""), "output": (el.get("output") or "").strip()}


def parse_host(h):
    host = {
        "address": "", "addr_type": "", "hostnames": [], "mac": "", "vendor": "",
        "status": "unknown", "reason": "", "latency_ms": None, "os": [],
        "uptime_s": None, "distance": None, "ports": [], "extraports": [],
        "hostscripts": [], "trace": [], "findings": [],
    }
    for a in h.findall("address"):
        t = a.get("addrtype", "")
        if t in ("ipv4", "ipv6") and not host["address"]:
            host["address"], host["addr_type"] = a.get("addr", ""), t
        elif t == "mac":
            host["mac"], host["vendor"] = a.get("addr", ""), a.get("vendor", "")
    if not host["address"]:
        a = h.find("address")
        host["address"] = a.get("addr", "") if a is not None else ""
    st = h.find("status")
    if st is not None:
        host["status"], host["reason"] = st.get("state", "unknown"), st.get("reason", "")
    for hn in h.findall("hostnames/hostname"):
        n = hn.get("name", "")
        if n and n not in host["hostnames"]:
            host["hostnames"].append(n)
    tm = h.find("times")
    if tm is not None and tm.get("srtt"):
        host["latency_ms"] = round(_int(tm.get("srtt")) / 1000.0, 2)
    for om in h.findall("os/osmatch")[:3]:
        host["os"].append({"name": om.get("name", ""), "accuracy": _int(om.get("accuracy"))})
    up = h.find("uptime")
    if up is not None:
        host["uptime_s"] = _int(up.get("seconds"), None)
    di = h.find("distance")
    if di is not None:
        host["distance"] = _int(di.get("value"), None)
    for ep in h.findall("ports/extraports"):
        host["extraports"].append({"state": ep.get("state", ""), "count": _int(ep.get("count"))})
    for p in h.findall("ports/port"):
        stp = p.find("state")
        sv = p.find("service")
        port = {
            "proto": p.get("protocol", "tcp"), "port": _int(p.get("portid")),
            "state": stp.get("state", "") if stp is not None else "",
            "reason": stp.get("reason", "") if stp is not None else "",
            "service": "", "product": "", "version": "", "extrainfo": "", "tunnel": "",
            "cpe": [], "scripts": [],
        }
        if sv is not None:
            for k in ("name", "product", "version", "extrainfo", "tunnel"):
                port["service" if k == "name" else k] = sv.get(k, "")
            port["cpe"] = [c.text for c in sv.findall("cpe") if c.text]
        port["scripts"] = [parse_script(s) for s in p.findall("script")]
        host["ports"].append(port)
    host["hostscripts"] = [parse_script(s) for s in h.findall("hostscript/script")]
    for hop in h.findall("trace/hop"):
        host["trace"].append({"ttl": _int(hop.get("ttl")), "ip": hop.get("ipaddr", ""),
                              "rtt": hop.get("rtt", ""), "host": hop.get("host", "")})
    return host


def parse_nmap_xml(path):
    root = load_xml(path)
    scan = {"file": os.path.basename(path), "args": root.get("args", ""), "start": _int(root.get("start")),
            "version": root.get("version", ""), "elapsed": 0.0, "summary": "", "hosts_up": None,
            "hosts_down": None, "hosts_total": None, "prescripts": [], "postscripts": []}
    fin = root.find("runstats/finished")
    if fin is not None:
        try:
            scan["elapsed"] = float(fin.get("elapsed", "0"))
        except ValueError:
            pass
        scan["summary"] = fin.get("summary", "")
    hs = root.find("runstats/hosts")
    if hs is not None:
        scan["hosts_up"], scan["hosts_down"], scan["hosts_total"] = (
            _int(hs.get("up")), _int(hs.get("down")), _int(hs.get("total")))
    scan["prescripts"] = [parse_script(s) for s in root.findall("prescript/script")]
    scan["postscripts"] = [parse_script(s) for s in root.findall("postscript/script")]
    hosts = [parse_host(h) for h in root.findall("host")]
    return scan, hosts


def merge_hosts(stages):
    """stages: list of host lists; later stages refine earlier ones."""
    merged = OrderedDict()
    for hosts in stages:
        for h in hosts:
            cur = merged.get(h["address"])
            if cur is None:
                merged[h["address"]] = h
                continue
            if h["status"] == "up":
                cur["status"], cur["reason"] = "up", h["reason"] or cur["reason"]
            for n in h["hostnames"]:
                if n not in cur["hostnames"]:
                    cur["hostnames"].append(n)
            for k in ("mac", "vendor"):
                cur[k] = h[k] or cur[k]
            for k in ("latency_ms", "uptime_s", "distance"):
                if h[k] is not None:
                    cur[k] = h[k]
            if h["os"]:
                cur["os"] = h["os"]
            if h["trace"]:
                cur["trace"] = h["trace"]
            if h["hostscripts"]:
                cur["hostscripts"] = h["hostscripts"]
            if h["extraports"]:
                cur["extraports"] = h["extraports"]
            index = {(p["proto"], p["port"]): i for i, p in enumerate(cur["ports"])}
            for p in h["ports"]:
                key = (p["proto"], p["port"])
                if key in index:
                    old = cur["ports"][index[key]]
                    # keep richer info
                    for f in ("service", "product", "version", "extrainfo", "tunnel"):
                        p[f] = p[f] or old[f]
                    p["cpe"] = p["cpe"] or old["cpe"]
                    p["scripts"] = p["scripts"] or old["scripts"]
                    cur["ports"][index[key]] = p
                else:
                    cur["ports"].append(p)
    for h in merged.values():
        h["ports"].sort(key=lambda p: (p["proto"], p["port"]))
    return list(merged.values())


# --------------------------------------------------------------------------- #
# Findings engine (heuristic hints, not a vulnerability verdict)
# --------------------------------------------------------------------------- #
PORT_RULES = {
    ("tcp", 23): ("HIGH", "Telnet exposed (cleartext remote shell)", "Disable Telnet; use SSH."),
    ("tcp", 21): ("MEDIUM", "FTP exposed (cleartext credentials)", "Use SFTP/FTPS; restrict by firewall."),
    ("udp", 69): ("MEDIUM", "TFTP exposed (unauthenticated file transfer)", "Disable or restrict TFTP."),
    ("tcp", 445): ("MEDIUM", "SMB exposed", "Restrict SMB to required hosts; disable SMBv1; require signing."),
    ("tcp", 135): ("LOW", "MS-RPC endpoint mapper exposed", "Filter at the network boundary."),
    ("tcp", 139): ("LOW", "NetBIOS session service exposed", "Disable NetBIOS over TCP/IP if unused."),
    ("tcp", 3389): ("MEDIUM", "RDP exposed", "Require NLA, restrict by VPN/firewall, enable MFA."),
    ("tcp", 5900): ("MEDIUM", "VNC exposed", "Tunnel over SSH/VPN; use strong authentication."),
    ("tcp", 512): ("HIGH", "rexec exposed", "Disable r-services."),
    ("tcp", 513): ("HIGH", "rlogin exposed", "Disable r-services."),
    ("tcp", 514): ("HIGH", "rsh exposed", "Disable r-services."),
    ("tcp", 2375): ("HIGH", "Docker API exposed without TLS", "Bind to a Unix socket or require mTLS."),
    ("tcp", 6000): ("LOW", "X11 server port exposed", "Disable remote X11 or tunnel over SSH."),
    ("tcp", 111): ("LOW", "rpcbind exposed", "Filter unless NFS/NIS is required."),
    ("udp", 161): ("LOW", "SNMP exposed", "Use SNMPv3; restrict by ACL."),
    ("tcp", 9100): ("LOW", "Raw print port (JetDirect/ESC-POS) open", "Restrict to POS/print VLAN; anyone reaching it can print."),
}
DB_PORTS = {1433: "Microsoft SQL Server", 1521: "Oracle TNS", 3306: "MySQL/MariaDB", 5432: "PostgreSQL",
            5984: "CouchDB", 6379: "Redis", 9042: "Cassandra", 9200: "Elasticsearch", 11211: "Memcached",
            27017: "MongoDB", 50000: "DB2"}
SERVICE_RULES = {
    "telnet": ("HIGH", "Telnet service detected (cleartext)", "Disable Telnet; use SSH."),
    "ftp": ("MEDIUM", "FTP service detected (cleartext credentials)", "Use SFTP/FTPS."),
    "vnc": ("MEDIUM", "VNC service detected", "Tunnel over SSH/VPN."),
    "ms-wbt-server": ("MEDIUM", "RDP service detected", "Require NLA; restrict by VPN/firewall."),
}


def add(findings, sev, host, port, title, detail="", advice="", source="heuristic"):
    findings.append({"severity": sev, "host": host["address"],
                     "port": port["port"] if port else None,
                     "proto": port["proto"] if port else None,
                     "title": title, "detail": detail[:600], "advice": advice, "source": source})


def analyze_script(findings, host, port, sc):
    sid, out = sc["id"], sc["output"]
    low = out.lower()
    where = port or None

    # generic NSE vulnerability markers
    if re.search(r"\bVULNERABLE\b", out) and not re.search(r"NOT VULNERABLE", out):
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", out)))
        sev = "CRITICAL" if ("smb-vuln" in sid or "ms17" in sid or "heartbleed" in sid) else "HIGH"
        if "LIKELY VULNERABLE" in out:
            sev = "HIGH"
        add(findings, sev, host, where, f"{sid}: reported VULNERABLE" + (f" ({', '.join(cves)})" if cves else ""),
            out, "Patch/mitigate and re-test; verify manually (NSE checks can have false positives).", sid)
    elif sid == "vulners" and "CVE-" in out:
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", out)))
        add(findings, "MEDIUM", host, where, f"vulners.com lists {len(cves)} CVE(s) for detected version",
            ", ".join(cves[:20]), "Version-based matching: confirm the product is actually affected (backports!).", sid)

    if sid == "ssl-enum-ciphers":
        for proto in ("SSLv3", "TLSv1.0", "TLSv1.1"):
            if re.search(rf"^\s*{re.escape(proto)}:", out, re.M):
                add(findings, "MEDIUM", host, where, f"Deprecated protocol enabled: {proto}", "", "Disable; require TLS 1.2+.", sid)
        m = re.search(r"least strength:\s*([A-F])", out)
        if m and m.group(1) in "CDEF":
            add(findings, "MEDIUM", host, where, f"Weak cipher strength grade {m.group(1)}", "", "Remove weak ciphers.", sid)
        if re.search(r"(?<![A-Za-z0-9])(NULL|EXPORT|RC4|DES_CBC|DES-CBC|anon)(?![A-Za-z0-9])", out):
            add(findings, "HIGH", host, where, "Insecure cipher suites offered (NULL/EXPORT/RC4/DES/anon)", "", "Remove them from the server config.", sid)
    elif sid == "ssl-cert":
        m = re.search(r"Not valid after:\s*(\d{4}-\d{2}-\d{2})", out)
        if m:
            try:
                end = dt.datetime.strptime(m.group(1), "%Y-%m-%d").date()
                days = (end - dt.date.today()).days
                if days < 0:
                    add(findings, "MEDIUM", host, where, f"TLS certificate expired {-days} day(s) ago", m.group(1), "Renew the certificate.", sid)
                elif days <= 30:
                    add(findings, "LOW", host, where, f"TLS certificate expires in {days} day(s)", m.group(1), "Renew soon.", sid)
            except ValueError:
                pass
        subj = re.search(r"Subject:\s*(.+)", out)
        iss = re.search(r"Issuer:\s*(.+)", out)
        if subj and iss and subj.group(1).strip() == iss.group(1).strip():
            add(findings, "LOW", host, where, "Self-signed TLS certificate", subj.group(1).strip()[:120],
                "Use a certificate from a trusted CA (e.g. Let's Encrypt) for user-facing services.", sid)
        if re.search(r"Signature Algorithm:\s*(sha1|md5)", out, re.I):
            add(findings, "MEDIUM", host, where, "Certificate signed with a weak hash (SHA-1/MD5)", "", "Reissue with SHA-256+.", sid)
    elif sid == "ssh2-enum-algos":
        weak = [a for a in ("diffie-hellman-group1-sha1", "arcfour", "3des-cbc", "blowfish-cbc", "hmac-md5", "hmac-sha1-96", "ssh-dss")
                if a in low]
        if weak:
            add(findings, "MEDIUM", host, where, "Weak SSH algorithms offered", ", ".join(weak), "Restrict KexAlgorithms/Ciphers/MACs in sshd_config.", sid)
    elif sid == "sshv1" and re.search(r"supports SSHv1|SSHv1 supported", out, re.I) and "does not" not in low:
        add(findings, "HIGH", host, where, "SSH protocol version 1 supported", "", "Disable Protocol 1.", sid)
    elif sid == "smb-protocols" and re.search(r"NT LM 0\.12|SMBv1", out):
        add(findings, "HIGH", host, where, "SMBv1 enabled", "", "Disable SMBv1 (legacy, exploited by WannaCry/EternalBlue).", sid)
    elif sid in ("smb2-security-mode", "smb-security-mode") and re.search(r"not required|message_signing:\s*disabled", low):
        add(findings, "MEDIUM", host, where, "SMB message signing not required", "", "Require SMB signing (relay-attack hardening).", sid)
    elif sid == "http-methods":
        m = re.search(r"Potentially risky methods:\s*(.+)", out)
        if m:
            add(findings, "MEDIUM", host, where, "Risky HTTP methods enabled", m.group(1).strip(), "Disable PUT/DELETE/TRACE unless required.", sid)
    elif sid == "http-title" and re.search(r"Index of /|Directory listing for /", out):
        add(findings, "LOW", host, where, "Web directory listing enabled", out[:120], "Disable autoindex.", sid)
    elif sid == "ftp-anon" and re.search(r"Anonymous FTP login allowed", out):
        add(findings, "HIGH", host, where, "Anonymous FTP login allowed", out[:200], "Disable anonymous access.", sid)
    elif sid == "redis-info" and out:
        add(findings, "HIGH", host, where, "Redis answers without authentication", out[:200], "Set requirepass/ACLs; bind to localhost/private interface.", sid)
    elif sid == "memcached-info" and out:
        add(findings, "HIGH", host, where, "Memcached accessible without authentication", out[:200], "Bind to localhost; disable UDP (amplification abuse).", sid)
    elif sid in ("couchdb-stats",) and out:
        add(findings, "HIGH", host, where, "CouchDB statistics readable without authentication", out[:200], "Require authentication.", sid)
    elif sid == "mongodb-info" and out:
        add(findings, "MEDIUM", host, where, "MongoDB server info readable without authentication", out[:200], "Enable auth; bind to private interface.", sid)
    elif sid == "rdp-enum-encryption" and re.search(r"Native RDP:\s*SUCCESS|RDP Security Layer", out) and "CredSSP (NLA): SUCCESS" not in out:
        add(findings, "MEDIUM", host, where, "RDP without Network Level Authentication", "", "Require NLA/CredSSP.", sid)
    elif sid == "dns-recursion" and "enabled" in low:
        add(findings, "MEDIUM", host, where, "Open recursive DNS resolver", "", "Restrict recursion to internal clients.", sid)
    elif sid == "odoo-info":
        fields = dict(re.findall(r"^\s*([a-z_]+):\s*(.+)$", out, re.M))
        ver = fields.get("version", "")
        if ver:
            add(findings, "INFO", host, where, f"Odoo {ver} detected", out[:300], "", sid)
            mm = re.match(r"(?:saas~)?(\d+)", ver)
            if mm and int(mm.group(1)) < ODOO_MIN_SUPPORTED:
                add(findings, "LOW", host, where, f"Odoo {ver} is likely out of support", "",
                    f"Plan an upgrade (toolkit considers < {ODOO_MIN_SUPPORTED}.0 unsupported).", sid)
        if "exposed" in fields.get("database_listing", "").lower():
            add(findings, "MEDIUM", host, where, "Odoo database listing is public", fields["database_listing"],
                "Set list_db = False in odoo.conf (and db_name/dbfilter).", sid)
        if "exposed" in fields.get("database_manager", "").lower():
            add(findings, "HIGH", host, where, "Odoo database manager page is reachable", fields["database_manager"],
                "Block /web/database/* at the proxy, set a strong admin_passwd, list_db = False.", sid)
        if "http" == fields.get("transport", "") and where and where["port"] not in (443, 8071):
            add(findings, "LOW", host, where, "Odoo served over plain HTTP", "", "Terminate TLS in a reverse proxy.", sid)


def analyze_host(host):
    f = []
    open_ports = [p for p in host["ports"] if p["state"] == "open"]
    ports_set = {p["port"] for p in open_ports if p["proto"] == "tcp"}
    for p in open_ports:
        rule = PORT_RULES.get((p["proto"], p["port"]))
        if rule:
            add(f, rule[0], host, p, rule[1], "", rule[2])
        elif p["service"] in SERVICE_RULES:
            r = SERVICE_RULES[p["service"]]
            add(f, r[0], host, p, r[1], "", r[2])
        if p["port"] in DB_PORTS:
            add(f, "MEDIUM", host, p, f"{DB_PORTS[p['port']]} port reachable from the scan origin",
                "", "Databases should listen on localhost/private VLAN only.")
        if p["port"] in (80, 8080, 8000) and 443 not in ports_set and p["service"].startswith("http") \
                and not p["tunnel"] == "ssl":
            add(f, "LOW", host, p, "Cleartext HTTP without HTTPS on the same host", "", "Redirect to HTTPS.")
        for sc in p["scripts"]:
            analyze_script(f, host, p, sc)
    for sc in host["hostscripts"]:
        analyze_script(f, host, None, sc)
    # deduplicate
    seen, out = set(), []
    for x in f:
        k = (x["host"], x["port"], x["proto"], x["title"])
        if k not in seen:
            seen.add(k)
            out.append(x)
    out.sort(key=lambda x: (SEV_RANK[x["severity"]], x["port"] or 0))
    return out


# --------------------------------------------------------------------------- #
# Report assembly
# --------------------------------------------------------------------------- #
def build_report(xml_paths, meta, latency=None):
    scans, stage_hosts = [], []
    for p in xml_paths:
        s, h = parse_nmap_xml(p)
        scans.append(s)
        stage_hosts.append(h)
    hosts = merge_hosts(stage_hosts)
    if latency:
        for h in hosts:
            if h["address"] in latency and latency[h["address"]] is not None:
                h["latency_ms"] = latency[h["address"]]
    findings = []
    for h in hosts:
        h["findings"] = analyze_host(h)
        findings.extend(h["findings"])
    for s in scans:  # broadcast / prerule scripts
        for sc in s["prescripts"] + s["postscripts"]:
            if sc["id"] == "broadcast-dhcp-discover" and sc["output"].count("Server Identifier") > 1:
                findings.append({"severity": "HIGH", "host": "(broadcast)", "port": None, "proto": None,
                                 "title": "Multiple DHCP servers answered (possible rogue DHCP)",
                                 "detail": sc["output"][:600], "advice": "Enable DHCP snooping on switches.",
                                 "source": sc["id"]})
    findings.sort(key=lambda x: (SEV_RANK[x["severity"]], x["host"], x["port"] or 0))
    for f in findings:
        f.setdefault("rule_id", rule_id_for(f))
        f.setdefault("suppressed", False)

    up = [h for h in hosts if h["status"] == "up"]
    open_total = sum(1 for h in hosts for p in h["ports"] if p["state"] == "open")
    services = Counter(p["service"] or "unknown" for h in hosts for p in h["ports"] if p["state"] == "open")
    sev = Counter(x["severity"] for x in findings)
    first = scans[0]
    hosts_total = first["hosts_total"] if first["hosts_total"] is not None else len(hosts)
    hosts_up = first["hosts_up"] if first["hosts_up"] is not None else len(up)
    if len(scans) > 1 and hosts:
        hosts_up = max(hosts_up, len(up))
    return {
        "schema": 1, "schema_version": 2, "generator": f"xamltech-nmap-toolkit {VERSION}",
        "generated": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "meta": meta,
        "scan": {"stages": scans, "elapsed": round(sum(s["elapsed"] for s in scans), 2),
                 "nmap_version": scans[-1]["version"], "args": scans[-1]["args"]},
        "stats": {"hosts_total": hosts_total, "hosts_up": hosts_up, "open_ports": open_total,
                  "services": dict(services.most_common()), "findings": {s: sev.get(s, 0) for s in SEVERITIES}},
        "hosts": hosts, "findings": findings,
        "prescripts": [sc for s in scans for sc in s["prescripts"] + s["postscripts"]],
    }


def read_latency(path):
    out = {}
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 2:
                    try:
                        out[parts[0]] = float(parts[1])
                    except ValueError:
                        out[parts[0]] = None
    return out


# ---- safe writers ---------------------------------------------------------- #
def csv_safe(v):
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def md_safe(v):
    return re.sub(r"\s+", " ", str(v if v is not None else "")).replace("|", "\\|").replace("`", "'").strip()


def host_label(h):
    return h["address"] + (f" ({h['hostnames'][0]})" if h["hostnames"] else "")


def write_csvs(rep, outdir):
    with open(os.path.join(outdir, "hosts.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["address", "hostname", "status", "mac", "vendor", "os", "latency_ms", "open_ports", "findings"])
        for h in rep["hosts"]:
            w.writerow([csv_safe(x) for x in (
                h["address"], ";".join(h["hostnames"]), h["status"], h["mac"], h["vendor"],
                h["os"][0]["name"] if h["os"] else "", h["latency_ms"] if h["latency_ms"] is not None else "",
                " ".join(f"{p['port']}/{p['proto']}" for p in h["ports"] if p["state"] == "open"), len(h["findings"]))])
    with open(os.path.join(outdir, "services.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["address", "hostname", "proto", "port", "state", "service", "product", "version", "extrainfo", "cpe"])
        for h in rep["hosts"]:
            for p in h["ports"]:
                w.writerow([csv_safe(x) for x in (
                    h["address"], ";".join(h["hostnames"]), p["proto"], p["port"], p["state"], p["service"],
                    p["product"], p["version"], p["extrainfo"], " ".join(p["cpe"]))])
    with open(os.path.join(outdir, "findings.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["rule_id", "severity", "host", "port", "proto", "title", "detail", "advice", "source"])
        for x in rep["findings"]:
            w.writerow([csv_safe(v) for v in (x.get("rule_id", ""), x["severity"], x["host"], x["port"] or "",
                                              x["proto"] or "", x["title"], x["detail"], x["advice"], x["source"])])


def write_markdown(rep, outdir):
    st, meta = rep["stats"], rep["meta"]
    L = ["# XamlTech Nmap Toolkit report", ""]
    L += [f"- **Target:** {md_safe(meta.get('targets', ''))}", f"- **Profile:** {md_safe(meta.get('profile', ''))}",
          f"- **Started:** {md_safe(meta.get('started', ''))}", f"- **Nmap:** {md_safe(rep['scan']['nmap_version'])}",
          f"- **Duration:** {rep['scan']['elapsed']}s", ""]
    L += ["## Summary", "", "| Hosts up | Open ports | Services | Critical | High | Medium | Low |", "|---|---|---|---|---|---|---|",
          f"| {st['hosts_up']}/{st['hosts_total']} | {st['open_ports']} | {len(st['services'])} | "
          f"{st['findings']['CRITICAL']} | {st['findings']['HIGH']} | {st['findings']['MEDIUM']} | {st['findings']['LOW']} |", ""]
    if rep["findings"]:
        L += ["## Findings", "", "> Heuristic hints derived from scan data - verify before acting.", "",
              "| Rule | Severity | Host | Port | Finding | Recommendation |", "|---|---|---|---|---|---|"]
        for x in rep["findings"]:
            port = f"{x['port']}/{x['proto']}" if x["port"] else "-"
            L.append(f"| {md_safe(x.get('rule_id', ''))} | {x['severity']} | {md_safe(x['host'])} | {port} | {md_safe(x['title'])} | {md_safe(x['advice'])} |")
        L.append("")
    L += ["## Hosts", ""]
    for h in rep["hosts"]:
        if h["status"] != "up" and not h["ports"]:
            continue
        L += [f"### {md_safe(host_label(h))}", ""]
        meta_bits = [f"status: {h['status']}"]
        if h["mac"]:
            meta_bits.append(f"MAC: {md_safe(h['mac'])} {md_safe(h['vendor'])}")
        if h["os"]:
            meta_bits.append(f"OS: {md_safe(h['os'][0]['name'])} ({h['os'][0]['accuracy']}%)")
        if h["latency_ms"] is not None:
            meta_bits.append(f"latency: {h['latency_ms']} ms")
        L += [" · ".join(meta_bits), ""]
        ports = [p for p in h["ports"] if p["state"] == "open"]
        if ports:
            L += ["| Port | Service | Product / version |", "|---|---|---|"]
            for p in ports:
                ver = " ".join(x for x in (p["product"], p["version"], p["extrainfo"]) if x)
                L.append(f"| {p['port']}/{p['proto']} | {md_safe(p['service'])} | {md_safe(ver)} |")
            L.append("")
    with open(os.path.join(outdir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


# --------------------------------------------------------------------------- #
# HTML report
# --------------------------------------------------------------------------- #
HTML_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>XamlTech Nmap Report - __TITLE__</title>
<style>
:root{--bg:#0b0f1a;--panel:#121a2b;--panel2:#18223a;--line:#24304d;--text:#e6ecff;--mut:#8a97b8;
--c1:#00e5ff;--c2:#bb00ff;--crit:#ff2d55;--high:#ff6b6b;--med:#ffb020;--low:#f5d90a;--info:#4cc9f0;--ok:#3ddc97}
@media (prefers-color-scheme:light){:root{--bg:#f5f7fc;--panel:#fff;--panel2:#eef2fb;--line:#d9e0f0;--text:#141b2d;--mut:#5b6785}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
header{padding:34px 5vw 26px;background:linear-gradient(120deg,var(--c1),var(--c2));color:#06101f}
header h1{margin:0;font-size:30px;letter-spacing:.5px}header p{margin:4px 0 0;opacity:.85}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}.chip{background:rgba(255,255,255,.28);padding:3px 11px;border-radius:99px;font-size:13px;color:#06101f}
main{padding:24px 5vw 60px;max-width:1280px;margin:auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:26px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px}
.card b{display:block;font-size:30px;line-height:1.1}.card span{color:var(--mut);font-size:13px;text-transform:uppercase;letter-spacing:.8px}
h2{margin:30px 0 12px;font-size:19px;border-left:4px solid var(--c1);padding-left:10px}
.sevbar{display:flex;height:14px;border-radius:99px;overflow:hidden;background:var(--panel2);margin:6px 0 4px}
.sevbar i{display:block}.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:13px;color:var(--mut)}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}
th{background:var(--panel2);color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.7px}tr:last-child td{border:0}
th.sortable{cursor:pointer;user-select:none}th.sortable:hover{color:var(--text)}th .arrow{opacity:.4;font-size:10px}
.diffgrid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.diffbox{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px}
.diffbox h3{margin:0 0 8px;font-size:14px;color:var(--mut);text-transform:uppercase;letter-spacing:.6px}
.diffbox ul{margin:0;padding-left:18px;font-size:13px}.plus{color:#1a8f5a}.minus{color:#c8414b}.chg{color:#a87516}
.sev{display:inline-block;padding:1px 9px;border-radius:6px;font-size:12px;font-weight:700;color:#06101f}
.CRITICAL{background:var(--crit);color:#fff}.HIGH{background:var(--high)}.MEDIUM{background:var(--med)}.LOW{background:var(--low)}.INFO{background:var(--info)}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:8px 0 14px}
input,button{background:var(--panel);border:1px solid var(--line);color:var(--text);padding:8px 12px;border-radius:9px;font:inherit}
button{cursor:pointer}button.on{border-color:var(--c1);box-shadow:0 0 0 1px var(--c1) inset}
details{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin-bottom:10px}
summary{cursor:pointer;padding:12px 16px;display:flex;gap:12px;align-items:center;flex-wrap:wrap;font-weight:600}
summary small{color:var(--mut);font-weight:400}.body{padding:0 16px 14px}
pre{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;font-size:12.5px;white-space:pre-wrap;word-break:break-word;margin:6px 0}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}.mut{color:var(--mut)}.tag{background:var(--panel2);border-radius:6px;padding:1px 7px;font-size:12px;margin-right:4px}
footer{color:var(--mut);font-size:12.5px;margin-top:40px;border-top:1px solid var(--line);padding-top:14px}
@media print{header{background:#fff;color:#000}.toolbar{display:none}details{break-inside:avoid}.diffgrid{break-inside:avoid}}
</style></head><body>
<header><h1>XamlTech Nmap Toolkit report</h1>
<p>__SUBTITLE__</p><div class="chips">__CHIPS__</div></header>
<main>
<div class="cards">__CARDS__</div>
<h2>Findings by severity</h2>__SEVBAR__
<h2>Findings</h2>
<div class="toolbar" id="sevfilter">__SEVBUTTONS__</div>
__FINDINGS__
<h2>Changes since previous run</h2>
__DIFF__
__PRESCRIPTS__
<h2>Hosts</h2>
<div class="toolbar"><input id="q" placeholder="Filter hosts, ports, services..." size="36"></div>
<div id="hosts">__HOSTS__</div>
<h2>Command</h2><pre class="mono">__COMMAND__</pre>
<footer>Generated by XamlTech Nmap Toolkit __VERSION__ at __GENERATED__. Findings are heuristic hints derived from scan output
and are not a substitute for a vulnerability assessment. Scan only systems you are authorized to test.</footer>
</main>
<script>
(function(){
var q=document.getElementById('q');
q.addEventListener('input',function(){var v=q.value.toLowerCase();
document.querySelectorAll('#hosts details').forEach(function(d){d.style.display=d.textContent.toLowerCase().indexOf(v)>-1?'':'none'})});
var btns=document.querySelectorAll('#sevfilter button');
btns.forEach(function(b){b.addEventListener('click',function(){
btns.forEach(function(x){x.classList.remove('on')});b.classList.add('on');var s=b.dataset.sev;
document.querySelectorAll('#ftable tbody tr').forEach(function(r){r.style.display=(s==='ALL'||r.dataset.sev===s)?'':'none'})})});
var rank={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
document.querySelectorAll('#ftable th').forEach(function(th,i){th.classList.add('sortable');
th.addEventListener('click',function(){var table=document.getElementById('ftable'),body=table.tBodies[0],
rows=Array.prototype.slice.call(body.rows),asc=th.dataset.dir!=='asc';th.dataset.dir=asc?'asc':'desc';
rows.sort(function(a,b){var x=a.cells[i]?a.cells[i].textContent.trim():'',y=b.cells[i]?b.cells[i].textContent.trim():'';
if(i===0){x=rank[a.dataset.sev];y=rank[b.dataset.sev]}var n=parseFloat(x),m=parseFloat(y);
if(!isNaN(n)&&!isNaN(m)){return asc?n-m:m-n}return asc?x.localeCompare(y):y.localeCompare(x)});
rows.forEach(function(r){body.appendChild(r)});var old=th.querySelector('.arrow');if(old)old.remove();
var ar=document.createElement('span');ar.className='arrow';ar.textContent=asc?' ▲':' ▼';th.appendChild(ar)})});
})();
</script></body></html>
"""


def esc(v):
    return html.escape("" if v is None else str(v), quote=True)


def html_diff(d):
    if not d:
        return '<p class="mut">No previous run was available for comparison.</p>'
    prev, curr = [], []
    prev += [f'<li class="minus">host gone: {esc(h)}</li>' for h in d["hosts_gone"]]
    curr += [f'<li class="plus">host up: {esc(h)}</li>' for h in d["hosts_new"]]
    prev += [f'<li class="minus">port closed: {esc(h)} {esc(p)}/{esc(n)}</li>' for h, p, n in d["ports_closed"]]
    curr += [f'<li class="plus">port opened: {esc(h)} {esc(p)}/{esc(n)}</li>' for h, p, n in d["ports_opened"]]
    for k, old, new in d["service_changed"]:
        host, proto, port = k
        prev.append(f'<li class="minus">{esc(host)} {esc(port)}/{esc(proto)}: {esc(old)}</li>')
        curr.append(f'<li class="plus">{esc(host)} {esc(port)}/{esc(proto)}: {esc(new)}</li>')
    prev += [f'<li class="minus">finding resolved: {esc(x[2])} ({esc(x[0])})</li>' for x in d["findings_resolved"]]
    curr += [f'<li class="plus">new finding: {esc(x["title"])} ({esc(x["host"])})</li>' for x in d["findings_new"]]
    if not prev and not curr:
        return '<p class="mut">No changes since the previous run.</p>'
    cell = lambda title, items: (f'<div class="diffbox"><h3>{title}</h3><ul>'
                                 + ("".join(items) or '<li class="mut">none</li>') + "</ul></div>")
    return '<div class="diffgrid">' + cell("Earlier run", prev) + cell("Current run", curr) + "</div>"


def write_html(rep, outdir, diff=None):
    st, meta = rep["stats"], rep["meta"]
    fnd = st["findings"]
    total_f = sum(fnd.values())
    chips = "".join(f'<span class="chip">{esc(k)}: {esc(v)}</span>' for k, v in (
        ("Target", meta.get("targets", "")), ("Profile", meta.get("profile", "")),
        ("Nmap", rep["scan"]["nmap_version"]), ("Duration", f"{rep['scan']['elapsed']}s")) if v)
    cards = "".join(f'<div class="card"><b>{esc(v)}</b><span>{esc(k)}</span></div>' for k, v in (
        ("Hosts up", f"{st['hosts_up']}/{st['hosts_total']}"), ("Open ports", st["open_ports"]),
        ("Services", len(st["services"])), ("Findings", total_f),
        ("Critical + High", fnd["CRITICAL"] + fnd["HIGH"])))
    colors = {"CRITICAL": "var(--crit)", "HIGH": "var(--high)", "MEDIUM": "var(--med)", "LOW": "var(--low)", "INFO": "var(--info)"}
    if total_f:
        bar = '<div class="sevbar">' + "".join(
            f'<i style="width:{fnd[s] * 100 / total_f:.2f}%;background:{colors[s]}"></i>' for s in SEVERITIES if fnd[s]) + "</div>"
    else:
        bar = '<div class="sevbar"></div>'
    legend = '<div class="legend">' + "".join(
        f'<span><span class="dot" style="background:{colors[s]}"></span>{s} {fnd[s]}</span>' for s in SEVERITIES) + "</div>"
    buttons = '<button class="on" data-sev="ALL">All</button>' + "".join(
        f'<button data-sev="{s}">{s} ({fnd[s]})</button>' for s in SEVERITIES if fnd[s])
    if rep["findings"]:
        rows = "".join(
            f'<tr data-sev="{x["severity"]}" data-rule="{esc(x.get("rule_id", ""))}"><td><span class="sev {x["severity"]}">{x["severity"]}</span></td>'
            f'<td class="mono">{esc(x.get("rule_id", ""))}</td>'
            f'<td class="mono">{esc(x["host"])}</td><td class="mono">{esc(str(x["port"]) + "/" + x["proto"]) if x["port"] else "-"}</td>'
            f'<td><b>{esc(x["title"])}</b>' + (f'<pre>{esc(x["detail"])}</pre>' if x["detail"] else "") + "</td>"
            f'<td class="mut">{esc(x["advice"])}</td></tr>' for x in rep["findings"])
        findings = ('<table id="ftable"><thead><tr>'
                    '<th class="sortable">Severity</th><th class="sortable">Rule</th><th class="sortable">Host</th>'
                    '<th class="sortable">Port</th><th class="sortable">Finding</th><th class="sortable">Recommendation</th>'
                    '</tr></thead>' f"<tbody>{rows}</tbody></table>")
    else:
        findings = '<p class="mut">No findings were derived from this scan.</p>'
    pre = ""
    if rep["prescripts"]:
        pre = "<h2>Network broadcast discovery</h2>" + "".join(
            f'<details><summary>{esc(sc["id"])}</summary><div class="body"><pre>{esc(sc["output"])}</pre></div></details>'
            for sc in rep["prescripts"])
    hosts_html = []
    for h in rep["hosts"]:
        if h["status"] != "up" and not h["ports"]:
            continue
        op = [p for p in h["ports"] if p["state"] == "open"]
        worst = h["findings"][0]["severity"] if h["findings"] else None
        head = f'<span class="mono">{esc(h["address"])}</span>'
        if h["hostnames"]:
            head += f' <small>{esc(h["hostnames"][0])}</small>'
        if worst:
            head += f' <span class="sev {worst}">{worst}</span>'
        head += f' <small>{len(op)} open</small>'
        body = []
        facts = []
        if h["mac"]:
            facts.append(f'<span class="tag">MAC {esc(h["mac"])} {esc(h["vendor"])}</span>')
        if h["os"]:
            facts.append(f'<span class="tag">OS {esc(h["os"][0]["name"])} ({h["os"][0]["accuracy"]}%)</span>')
        if h["latency_ms"] is not None:
            facts.append(f'<span class="tag">{h["latency_ms"]} ms</span>')
        if h["distance"] is not None:
            facts.append(f'<span class="tag">{h["distance"]} hops</span>')
        if facts:
            body.append("<p>" + "".join(facts) + "</p>")
        if op:
            prow = ""
            for p in op:
                ver = " ".join(x for x in (p["product"], p["version"], p["extrainfo"]) if x)
                sc = "".join(f'<details><summary class="mono">{esc(s["id"])}</summary><pre>{esc(s["output"])}</pre></details>' for s in p["scripts"])
                prow += (f'<tr><td class="mono">{p["port"]}/{esc(p["proto"])}</td><td>{esc(p["service"])}</td>'
                         f'<td>{esc(ver)}{sc}</td></tr>')
            body.append(f'<table><thead><tr><th>Port</th><th>Service</th><th>Version / scripts</th></tr></thead><tbody>{prow}</tbody></table>')
        for s in h["hostscripts"]:
            body.append(f'<details><summary class="mono">{esc(s["id"])}</summary><pre>{esc(s["output"])}</pre></details>')
        if h["trace"]:
            body.append('<p class="mut mono">traceroute: ' + " → ".join(esc(t["ip"]) for t in h["trace"]) + "</p>")
        hosts_html.append(f'<details><summary>{head}</summary><div class="body">{"".join(body)}</div></details>')
    cmd = (rep["meta"].get("command") or rep["scan"]["args"] or "")
    page = (HTML_TEMPLATE
            .replace("__TITLE__", esc(meta.get("targets", "")))
            .replace("__SUBTITLE__", esc(f"{meta.get('profile', 'scan')} profile · {rep['generated']}"))
            .replace("__CHIPS__", chips).replace("__CARDS__", cards)
            .replace("__SEVBAR__", bar + legend).replace("__SEVBUTTONS__", buttons)
            .replace("__FINDINGS__", findings).replace("__DIFF__", html_diff(diff)).replace("__PRESCRIPTS__", pre)
            .replace("__HOSTS__", "".join(hosts_html) or '<p class="mut">No hosts to display.</p>')
            .replace("__COMMAND__", esc(cmd)).replace("__VERSION__", esc(VERSION))
            .replace("__GENERATED__", esc(rep["generated"])))
    with open(os.path.join(outdir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(page)


# --------------------------------------------------------------------------- #
# Terminal rendering
# --------------------------------------------------------------------------- #
class Term:
    def __init__(self, color, width):
        self.c = color
        self.w = max(60, min(width, 120))
        self.utf8 = "utf" in (os.environ.get("LC_ALL") or os.environ.get("LC_CTYPE") or os.environ.get("LANG") or "").lower()

    def s(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.c else str(text)

    def sev(self, sev):
        codes = {"CRITICAL": "1;97;48;5;160", "HIGH": "1;38;5;203", "MEDIUM": "38;5;214", "LOW": "38;5;221", "INFO": "38;5;80"}
        return self.s(codes[sev], f"{sev:<8}")

    def bar(self, v, m, width=20):
        on, off = ("█", "░") if self.utf8 else ("#", ".")
        n = 0 if m <= 0 else max(1 if v else 0, round(v * width / m))
        return self.s("38;5;80", on * n) + self.s("38;5;240", off * (width - n))

    def head(self, title):
        line = ("─" if self.utf8 else "-") * max(4, self.w - len(title) - 5)
        return "\n" + self.s("38;5;80", "── ") + self.s("1", title) + " " + self.s("38;5;80", line)


def plain_len(s):
    return len(re.sub(r"\033\[[0-9;]*m", "", s))


def dashboard(rep, term):
    st = rep["stats"]
    out = [term.head("Results")]
    tiles = [("HOSTS UP", f"{st['hosts_up']}/{st['hosts_total']}", "38;5;84"), ("OPEN PORTS", st["open_ports"], "38;5;80"),
             ("SERVICES", len(st["services"]), "38;5;177"), ("FINDINGS", sum(st["findings"].values()), "38;5;214"),
             ("DURATION", f"{int(rep['scan']['elapsed'])}s", "38;5;245")]
    out.append("  " + "    ".join(term.s("38;5;245", k) + " " + term.s("1;" + c, v) for k, v, c in tiles))

    fnd = st["findings"]
    if sum(fnd.values()):
        out.append(term.head("Findings by severity"))
        mx = max(fnd.values())
        for s in SEVERITIES:
            if fnd[s]:
                out.append(f"  {term.sev(s)} {term.bar(fnd[s], mx, 24)} {fnd[s]}")
    hosts = [h for h in rep["hosts"] if h["status"] == "up" or h["ports"]]
    if hosts:
        out.append(term.head(f"Hosts ({len(hosts)})"))
        out.append("  " + term.s("38;5;245", f"{'ADDRESS':<18}{'NAME / OS':<28}OPEN PORTS"))
        for h in hosts[:14]:
            name = (h["hostnames"][0] if h["hostnames"] else (h["os"][0]["name"] if h["os"] else h["vendor"] or ""))[:26]
            op = [p for p in h["ports"] if p["state"] == "open"]
            portstr = " ".join(f"{p['port']}" + (f"/{p['service']}" if p["service"] else "") for p in op[:7])
            if len(op) > 7:
                portstr += f" +{len(op) - 7}"
            worst = h["findings"][0]["severity"] if h["findings"] else None
            mark = term.s({"CRITICAL": "1;38;5;196", "HIGH": "38;5;203", "MEDIUM": "38;5;214"}.get(worst, "38;5;84"), "●" if term.utf8 else "*")
            out.append(f"  {h['address']:<18}{name:<28}{term.s('38;5;84', portstr) if portstr else term.s('38;5;245', '-')} {mark}")
        if len(hosts) > 14:
            out.append(term.s("38;5;245", f"  ... and {len(hosts) - 14} more (see report)"))
    if st["services"]:
        out.append(term.head("Top services"))
        top = list(st["services"].items())[:6]
        mx = top[0][1]
        for name, n in top:
            out.append(f"  {name:<18} {term.bar(n, mx, 22)} {n}")
    if rep["findings"]:
        out.append(term.head("Top findings"))
        for x in rep["findings"][:8]:
            where = f"{x['host']}:{x['port']}" if x["port"] else x["host"]
            out.append(f"  {term.sev(x['severity'])} {term.s('38;5;245', where):<{22 + (len(term.s('38;5;245', '')) if term.c else 0)}} {x['title'][:max(20, term.w - 40)]}")
        if len(rep["findings"]) > 8:
            out.append(term.s("38;5;245", f"  ... {len(rep['findings']) - 8} more in report.html / findings.csv"))
        out.append(term.s("38;5;245", "  Heuristic hints from scan data - verify before acting."))
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Diff
# --------------------------------------------------------------------------- #
def load_report(path):
    if os.path.isdir(path):
        path = os.path.join(path, "report.json")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def rule_id_for(f):
    source = re.sub(r"[^A-Za-z0-9]", "-", str(f.get("source") or "generic")).upper()
    digest = hashlib.sha1((str(f.get("title", "")) + str(f.get("host", ""))).encode()).hexdigest()[:6]
    return f"XT-{source[:18].strip('-') or 'GENERIC'}-{digest}"


def finding_key(f):
    return (f.get("severity", ""), f.get("host", ""), f.get("port"), f.get("proto", ""),
            f.get("title", ""), f.get("source", ""))


def finding_key_str(f):
    payload = json.dumps(finding_key(f), sort_keys=True, default=list).encode()
    return hashlib.sha256(payload).hexdigest()[:16]


def load_baseline(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return set(data.get("suppressed", []))


def apply_baseline(rep, suppressed):
    count = 0
    for f in rep.get("findings", []):
        if finding_key_str(f) in suppressed:
            f["suppressed"] = True
            count += 1
    rep.setdefault("baseline", {})["suppressed_count"] = count
    return count


def port_map(rep):
    m = {}
    for h in rep["hosts"]:
        for p in h["ports"]:
            if p["state"] == "open":
                m[(h["address"], p["proto"], p["port"])] = " ".join(x for x in (p["service"], p["product"], p["version"]) if x)
    return m


def compute_diff(a, b):
    ha = {h["address"] for h in a["hosts"] if h["status"] == "up"}
    hb = {h["address"] for h in b["hosts"] if h["status"] == "up"}
    pa, pb = port_map(a), port_map(b)
    fa = {(x["host"], x["port"], x["title"]) for x in a["findings"]}
    fb = {(x["host"], x["port"], x["title"]): x for x in b["findings"]}
    return {
        "hosts_new": sorted(hb - ha, key=lambda s: [int(t) if t.isdigit() else t for t in re.split(r"[.:]", s)]),
        "hosts_gone": sorted(ha - hb, key=lambda s: [int(t) if t.isdigit() else t for t in re.split(r"[.:]", s)]),
        "ports_opened": sorted(k for k in pb if k not in pa and k[0] in (ha & hb)),
        "ports_closed": sorted(k for k in pa if k not in pb and k[0] in (ha & hb)),
        "service_changed": sorted((k, pa[k], pb[k]) for k in pa if k in pb and pa[k] != pb[k]),
        "findings_new": [fb[k] for k in fb if k not in fa],
        "findings_resolved": sorted((k for k in fa if k not in fb),
                                    key=lambda k: (k[0], k[1] or 0, k[2])),
    }


def diff_text(d, term):
    lines = []
    plus, minus, chg = term.s("1;38;5;84", "+"), term.s("1;38;5;203", "-"), term.s("1;38;5;221", "~")
    for h in d["hosts_new"]:
        lines.append(f"  {plus} host up        {h}")
    for h in d["hosts_gone"]:
        lines.append(f"  {minus} host gone      {h}")
    for h, proto, port in d["ports_opened"]:
        lines.append(f"  {plus} port opened    {h} {port}/{proto}")
    for h, proto, port in d["ports_closed"]:
        lines.append(f"  {minus} port closed    {h} {port}/{proto}")
    for (h, proto, port), old, new in d["service_changed"]:
        lines.append(f"  {chg} service change {h} {port}/{proto}: {old or '?'} -> {new or '?'}")
    for x in d["findings_new"]:
        lines.append(f"  {plus} finding        [{x['severity']}] {x['host']}{':' + str(x['port']) if x['port'] else ''} {x['title']}")
    for h, port, title in d["findings_resolved"]:
        lines.append(f"  {minus} resolved       {h}{':' + str(port) if port else ''} {title}")
    return "\n".join(lines) if lines else "  " + term.s("38;5;84", "No changes detected.")


# --------------------------------------------------------------------------- #
# History
# --------------------------------------------------------------------------- #
def history(root, term):
    rows = []
    for name in sorted(os.listdir(root), reverse=True):
        d = os.path.join(root, name)
        rp = os.path.join(d, "report.json")
        if not os.path.isdir(d) or name == "latest":
            continue
        row = {"name": name, "profile": "?", "targets": "?", "up": "-", "ports": "-", "sev": "-", "html": os.path.exists(os.path.join(d, "report.html"))}
        try:
            if os.path.exists(rp):
                r = load_report(rp)
                row.update(profile=r["meta"].get("profile", "?"), targets=r["meta"].get("targets", "?"),
                           up=f"{r['stats']['hosts_up']}", ports=f"{r['stats']['open_ports']}",
                           sev=f"{r['stats']['findings']['CRITICAL']}/{r['stats']['findings']['HIGH']}")
            elif os.path.exists(os.path.join(d, "metadata.json")):
                with open(os.path.join(d, "metadata.json"), encoding="utf-8") as mf:
                    m = json.load(mf)
                row.update(profile=m.get("profile", "?"), targets=m.get("targets", "?"))
            else:
                continue
        except (OSError, ValueError, KeyError):
            continue
        rows.append(row)
    out = [term.head(f"Scan history ({len(rows)})")]
    if not rows:
        out.append("  No runs found in " + root)
        return "\n".join(out)
    out.append("  " + term.s("38;5;245", f"{'RUN':<36}{'PROFILE':<13}{'TARGET':<22}{'UP':>4}{'PORTS':>7}{'C/H':>6}"))
    for r in rows[:40]:
        out.append(f"  {r['name'][:35]:<36}{r['profile'][:12]:<13}{r['targets'][:21]:<22}{r['up']:>4}{r['ports']:>7}{r['sev']:>6}")
    out.append(term.s("38;5;245", "\n  Compare:  nmap-toolkit.sh --diff <runA> <runB>     Open:  nmap-toolkit.sh --open-report <run|latest>"))
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Targets: classify & scope
# --------------------------------------------------------------------------- #
LOCAL_SUFFIXES = (".local", ".lan", ".home.arpa", ".internal", ".localdomain", ".intranet", ".corp")


def octet_expand(token, limit=65536):
    """Expand nmap-style IPv4 octet ranges (10.0.0-1.1-254, 10.0.0.1,5). None if too large/unsupported."""
    parts = token.split(".")
    if len(parts) != 4:
        return None
    sets = []
    for p in parts:
        vals = []
        for piece in p.split(","):
            if piece == "*":
                vals += list(range(256))
            elif re.fullmatch(r"\d{1,3}", piece):
                vals.append(int(piece))
            elif re.fullmatch(r"\d{1,3}-\d{1,3}", piece):
                lo, hi = map(int, piece.split("-"))
                vals += list(range(lo, hi + 1))
            else:
                return None
        if not vals or max(vals) > 255:
            return None
        sets.append(sorted(set(vals)))
    total = 1
    for s in sets:
        total *= len(s)
    if total > limit:
        return None
    return [".".join(map(str, c)) for c in itertools.product(*sets)]


def _resolve(host, timeout=3.0):
    res = []

    def work():
        try:
            for fam, _t, _p, _c, sa in socket.getaddrinfo(host, None):
                res.append(sa[0])
        except OSError:
            pass
    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    return res


def classify_token(tok):
    try:
        net = ipaddress.ip_network(tok, strict=False)
        return "internal" if (net.is_private or net.is_loopback or net.is_link_local) else "external"
    except ValueError:
        pass
    if re.fullmatch(r"[0-9.,*\-]+", tok):
        ips = octet_expand(tok, 4096)
        if ips is None:
            return "unknown"
        priv = all(ipaddress.ip_address(i).is_private or ipaddress.ip_address(i).is_loopback for i in ips)
        return "internal" if priv else "external"
    low = tok.lower().rstrip(".")
    if low == "localhost" or low.endswith(LOCAL_SUFFIXES) or "." not in low:
        return "internal"
    ips = _resolve(tok)
    if not ips:
        return "unknown"
    for i in ips:
        try:
            a = ipaddress.ip_address(i.split("%")[0])
        except ValueError:
            return "unknown"
        if not (a.is_private or a.is_loopback or a.is_link_local):
            return "external"
    return "internal"


def cmd_classify(targets):
    ranks = {"internal": 0, "unknown": 1, "external": 2}
    worst = "internal"
    for t in targets:
        c = classify_token(t)
        if ranks[c] > ranks[worst]:
            worst = c
    print(worst)


def cmd_scope(scope_file, targets):
    nets, names, deny_nets, deny_names = [], [], [], []
    max_hosts, valid_from, valid_until = None, None, None
    with open(scope_file, encoding="utf-8") as fh:
        raw_scope = fh.read()
    if raw_scope.lstrip().startswith("{"):
        data = json.loads(raw_scope)
        allow = data.get("allow", [])
        deny = data.get("deny", [])
        for entry in allow + deny:
            try:
                (nets if entry in allow else deny_nets).append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                (names if entry in allow else deny_names).append(str(entry).lower())
        max_hosts = data.get("max_hosts")
        valid_from = data.get("valid_from")
        valid_until = data.get("valid_until")
        expires = data.get("expires")
        now = dt.datetime.now().astimezone()
        for label, value in (("valid_from", valid_from), ("valid_until", valid_until), ("expires", expires)):
            if not value:
                continue
            try:
                moment = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                print(f"  invalid {label} in scope file: {value}")
                sys.exit(4)
            if moment.tzinfo is None:
                moment = moment.astimezone()
            if (label == "valid_from" and now < moment) or (label != "valid_from" and now > moment):
                print(f"  scope {label} violation: {value}")
                sys.exit(4)
        if max_hosts is not None and len(targets) > int(max_hosts):
            print(f"  too many targets: {len(targets)} > max_hosts={max_hosts}")
            sys.exit(4)
    else:
      with open(scope_file, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
                continue
            except ValueError:
                pass
            m = re.fullmatch(r"(\S+)\s*-\s*(\S+)", line)
            if m:
                try:
                    lo, hi = ipaddress.ip_address(m.group(1)), ipaddress.ip_address(m.group(2))
                    nets += list(ipaddress.summarize_address_range(lo, hi))
                    continue
                except ValueError:
                    pass
            names.append(line.lower())

    def ip_ok(ip):
        a = ipaddress.ip_address(ip.split("%")[0])
        return any(a in n for n in nets if n.version == a.version)

    def name_ok(name):
        n = name.lower().rstrip(".")
        for s in names:
            if s == n or (s.startswith("*.") and n.endswith(s[1:])):
                return True
        return False

    def denied(name):
        low = name.lower().rstrip(".")
        if any(low == s or (s.startswith("*.") and low.endswith(s[1:])) for s in deny_names):
            return True
        try:
            addr = ipaddress.ip_address(name.split("%")[0])
            return any(addr in n for n in deny_nets if n.version == addr.version)
        except ValueError:
            return False

    bad = []
    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
            ok = any(net.version == n.version and net.subnet_of(n) for n in nets)
        except ValueError:
            ips = octet_expand(t) if re.fullmatch(r"[0-9.,*\-]+", t) else None
            if re.fullmatch(r"[0-9.,*\-]+", t):
                ok = ips is not None and all(ip_ok(i) for i in ips)
                if ips is None:
                    print(f"  {t}: range too large to verify against the scope file (use CIDR)")
            elif name_ok(t):
                ok = True
            else:
                resolved = _resolve(t)
                ok = bool(resolved) and all(ip_ok(i) for i in resolved)
        if denied(t):
            ok = False
            print(f"  explicitly denied: {t}")
        if not ok:
            bad.append(t)
            print(f"  out of scope: {t}")
    sys.exit(4 if bad else 0)


# --------------------------------------------------------------------------- #
# CI integrations
# --------------------------------------------------------------------------- #
def sarif_level(sev):
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(sev, "note")


def build_sarif(rep):
    findings = [f for f in rep.get("findings", []) if not f.get("suppressed")]
    rules, seen = [], set()
    for f in findings:
        rid = f.get("rule_id") or rule_id_for(f)
        if rid in seen:
            continue
        seen.add(rid)
        rules.append({"id": rid, "name": rid, "shortDescription": {"text": f.get("title", "Finding")},
                      "defaultConfiguration": {"level": sarif_level(f.get("severity", "LOW"))}})
    results = []
    for f in findings:
        loc = {"physicalLocation": {"artifactLocation": {"uri": "nmap.xml"},
                                    "region": {"startLine": 1}}}
        if f.get("host"):
            loc["logicalLocations"] = [{"name": str(f["host"]),
                                        "fullyQualifiedName": f"{f['host']}:{f.get('port') or ''}"}]
        results.append({"ruleId": f.get("rule_id") or rule_id_for(f),
                        "level": sarif_level(f.get("severity", "LOW")),
                        "message": {"text": f.get("title", "Finding")},
                        "locations": [loc]})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "xamltech-nmap-toolkit",
                                          "version": rep.get("generator", VERSION), "rules": rules}},
                      "results": results}]}


def cmd_sarif(a):
    rep = load_report(a.run)
    data = build_sarif(rep)
    with open(a.output, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def cmd_baseline(a):
    if a.action == "create":
        rep = load_report(a.run)
        keys = sorted(finding_key_str(f) for f in rep.get("findings", []))
        with open(a.baseline, "w", encoding="utf-8") as fh:
            json.dump({"schema_version": 1, "generated": dt.datetime.now().astimezone().isoformat(),
                       "suppressed": keys}, fh, indent=2)
        print(f"Baseline written: {len(keys)} findings")
    else:
        keys = load_baseline(a.baseline)
        rep = load_report(a.run)
        matched = sum(1 for f in rep.get("findings", []) if finding_key_str(f) in keys)
        print(f"Matches: {matched}")
        sys.exit(0 if matched else 1)


def notify(a, rep):
    payload = json.dumps({"tool": "xamltech-nmap-toolkit", "version": VERSION,
                          "generated": rep.get("generated", ""),
                          "stats": rep.get("stats", {}),
                          "findings": rep.get("findings", [])[:50]}, default=list).encode()
    if getattr(a, "webhook", None):
        from urllib.request import Request, urlopen
        req = Request(a.webhook, data=payload, headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=5):
                pass
        except Exception as exc:
            print(f"webhook notification failed: {exc}", file=sys.stderr)
    if getattr(a, "email", None) and shutil.which("sendmail"):
        import subprocess
        text = f"Subject: XamlTech scan complete\n\n{rep.get('stats', {})}\n".encode()
        try:
            subprocess.run(["sendmail", a.email], input=text, timeout=5, check=False)
        except Exception as exc:
            print(f"email notification failed: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def cmd_export(a):
    """Plain-text handoff lists for other tools (ZAP/Burp, Masscan, OpenVAS, ...). Addresses only."""
    rep = load_report(a.run)
    up = [h for h in rep["hosts"] if h["status"] == "up" or h["ports"]]
    out = []
    if a.kind == "hosts":
        out = [h["address"] for h in up]
    elif a.kind == "openvas":
        out = [",".join(h["address"] for h in up)]
    elif a.kind == "hostports":
        out = [f"{h['address']}:{p['port']}" for h in up for p in h["ports"] if p["state"] == "open"]
    elif a.kind == "ports":
        out = [",".join(str(x) for x in sorted({p["port"] for h in up for p in h["ports"]
                                                 if p["state"] == "open" and p["proto"] == "tcp"}))]
    elif a.kind == "urls":
        for h in up:
            for p in h["ports"]:
                if p["state"] != "open" or p["proto"] != "tcp":
                    continue
                svc = p["service"]
                if not (svc.startswith("http") or p["tunnel"] == "ssl" and svc in ("http", "https", "")):
                    continue
                tls = svc.startswith("https") or p["tunnel"] == "ssl"
                host = f"[{h['address']}]" if h["addr_type"] == "ipv6" else h["address"]
                default = (tls and p["port"] == 443) or (not tls and p["port"] == 80)
                out.append(f"{'https' if tls else 'http'}://{host}" + ("" if default else f":{p['port']}"))
    if a.kind == "csv-coords":
        out = ["host,port,proto,service"]
        out += [f"{h['address']},{p['port']},{p['proto']},{p['service']}" for h in up for p in h["ports"]
                if p["state"] == "open"]
    elif a.kind == "json-arm":
        out = [json.dumps([{"ip": h["address"], "ports": [p["port"] for p in h["ports"] if p["state"] == "open"]}
                           for h in up])]
    print("\n".join(out))


def cmd_report(a):
    meta = {}
    if a.meta and os.path.exists(a.meta):
        try:
            with open(a.meta, encoding="utf-8") as mf:
                meta = json.load(mf)
        except ValueError:
            meta = {}
    cmdfile = os.path.join(a.outdir, "command.txt")
    if os.path.exists(cmdfile):
        with open(cmdfile, encoding="utf-8") as cf:
            meta["command"] = cf.read().strip()
    rep = build_report(a.xml, meta, read_latency(a.latency))
    os.makedirs(a.outdir, exist_ok=True)
    rep["integrity"] = {"native_sha256": {os.path.basename(p): file_sha256(p) for p in a.xml if os.path.isfile(p)}}
    if getattr(a, "baseline", None):
        apply_baseline(rep, load_baseline(a.baseline))
    fmts = {f.strip() for f in a.formats.split(",") if f.strip()}
    with open(os.path.join(a.outdir, "report.json"), "w", encoding="utf-8") as fh:   # always: diff/history depend on it
        json.dump(rep, fh, indent=2, ensure_ascii=False)
    if "csv" in fmts:
        write_csvs(rep, a.outdir)
    if "md" in fmts:
        write_markdown(rep, a.outdir)
    if "html" in fmts:
        diff = None
        if getattr(a, "diff_report", None) and os.path.isfile(a.diff_report):
            try:
                diff = compute_diff(load_report(a.diff_report), rep)
            except (ValueError, KeyError, OSError):
                diff = None
        write_html(rep, a.outdir, diff)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="report.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("version")
    p = sub.add_parser("report")
    p.add_argument("--xml", nargs="+", required=True)
    p.add_argument("--outdir", required=True)
    p.add_argument("--meta")
    p.add_argument("--latency")
    p.add_argument("--formats", default="json,csv,md,html")
    p.add_argument("--baseline")
    p.add_argument("--diff-report")
    p.add_argument("--webhook")
    p.add_argument("--email")
    p = sub.add_parser("sarif")
    p.add_argument("run"); p.add_argument("-o", "--output", required=True)
    p = sub.add_parser("baseline")
    p.add_argument("action", choices=["create", "check"])
    p.add_argument("run"); p.add_argument("-b", "--baseline", required=True)
    p = sub.add_parser("dashboard")
    p.add_argument("json"); p.add_argument("--color", action="store_true"); p.add_argument("--width", type=int, default=100)
    p = sub.add_parser("diff")
    p.add_argument("a"); p.add_argument("b"); p.add_argument("--color", action="store_true")
    p.add_argument("--json", action="store_true"); p.add_argument("--fail-on-change", action="store_true")
    p.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "critical", "high", "medium", "low"])
    p = sub.add_parser("history")
    p.add_argument("root"); p.add_argument("--color", action="store_true"); p.add_argument("--width", type=int, default=100)
    for name in ("hosts-up", "hosts-open", "ports"):
        p = sub.add_parser(name)
        p.add_argument("xml")
    p = sub.add_parser("export")
    p.add_argument("kind", choices=["hosts", "hostports", "ports", "urls", "openvas", "csv-coords", "json-arm"]); p.add_argument("run")
    p = sub.add_parser("classify"); p.add_argument("targets", nargs="+")
    p = sub.add_parser("scope"); p.add_argument("file"); p.add_argument("targets", nargs="+")
    a = ap.parse_args(argv)

    try:
        if a.cmd == "version":
            print(VERSION)
        elif a.cmd == "report":
            cmd_report(a)
            notify(a, load_report(os.path.join(a.outdir, "report.json")))
        elif a.cmd == "sarif":
            cmd_sarif(a)
        elif a.cmd == "baseline":
            cmd_baseline(a)
        elif a.cmd == "dashboard":
            print(dashboard(load_report(a.json), Term(a.color, a.width)))
        elif a.cmd == "diff":
            d = compute_diff(load_report(a.a), load_report(a.b))
            if a.json:
                print(json.dumps(d, indent=2, default=list))
            else:
                print(diff_text(d, Term(a.color, 100)))
            changed = any(d[k] for k in d)
            if getattr(a, "fail_on", None):
                rank = SEV_RANK[a.fail_on.upper()]
                severe = any(SEV_RANK.get(x.get("severity", "LOW"), 99) <= rank for x in d["findings_new"])
                sys.exit(10 if severe else 0)
            sys.exit(10 if (a.fail_on_change and changed) else 0)
        elif a.cmd == "history":
            print(history(a.root, Term(a.color, a.width)))
        elif a.cmd in ("hosts-up", "hosts-open", "ports"):
            _scan, hosts = parse_nmap_xml(a.xml)
            if a.cmd == "hosts-up":
                print("".join(h["address"] + "\n" for h in hosts if h["status"] == "up"), end="")
            elif a.cmd == "hosts-open":
                print("".join(h["address"] + "\n" for h in hosts if any(p["state"] == "open" for p in h["ports"])), end="")
            else:
                tcp = sorted({p["port"] for h in hosts for p in h["ports"] if p["state"] == "open" and p["proto"] == "tcp"})
                udp = sorted({p["port"] for h in hosts for p in h["ports"] if p["state"] == "open" and p["proto"] == "udp"})
                parts = []
                if tcp:
                    parts.append(("T:" if udp else "") + ",".join(map(str, tcp)))
                if udp:
                    parts.append("U:" + ",".join(map(str, udp)))
                print(",".join(parts))
        elif a.cmd == "export":
            cmd_export(a)
        elif a.cmd == "classify":
            cmd_classify(a.targets)
        elif a.cmd == "scope":
            cmd_scope(a.file, a.targets)
    except (OSError, ValueError, KeyError) as exc:
        print(f"report.py: {exc}", file=sys.stderr)
        sys.exit(2)
    except BrokenPipeError:
        sys.exit(0)


if __name__ == "__main__":
    main()
