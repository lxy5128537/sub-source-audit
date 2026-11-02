"""订阅源 → mihomo 节点对象。

支持三种输入形态：
  1. Clash YAML（含 proxies: 段）—— 直接取用，保真度最高
  2. 整段 base64 订阅 —— 解开后按 URI 行处理
  3. 明文分享链接（vmess/vless/trojan/ss/ssr/hysteria/hysteria2/tuic）—— 逐行转换

输出统一为 mihomo 的 proxy dict，并尽量保留原始 URI 行（便于结果回写）。
"""
from __future__ import annotations

import base64
import ipaddress
import json
import random
import re
import ssl
import urllib.parse
import urllib.request

UA = {"User-Agent": "clash-verge/v2.4.3 mihomo/1.19.9"}
URI_RE = re.compile(r"(?m)^(vmess|vless|trojan|ss|ssr|hysteria2|hy2|hysteria|tuic)://\S+")
PRIVATE_HOST_RE = re.compile(r"^(localhost|127\.|0\.0\.0\.0|::1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")
SUPPORTED = {"vmess", "vless", "trojan", "ss", "ssr", "hysteria", "hysteria2", "tuic"}


def http_get(url: str, timeout: int = 30) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read().decode("utf-8", "ignore")


def b64d(text: str) -> str:
    s = re.sub(r"\s+", "", text).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", "ignore")
    except Exception:
        return ""


def _int(v, default=0):
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _q(query: str) -> dict:
    out = {}
    for kv in (query or "").split("&"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            out[k.lower()] = urllib.parse.unquote(v)
    return out


def parse_uri(line: str) -> dict | None:
    line = line.strip()
    if "://" not in line:
        return None
    scheme, _, rest = line.partition("://")
    scheme = scheme.lower()
    if scheme == "hy2":
        scheme = "hysteria2"
    if scheme not in SUPPORTED:
        return None

    if scheme == "vmess":
        try:
            j = json.loads(b64d(rest.split("#")[0]))
        except Exception:
            return None
        srv, port = j.get("add"), _int(j.get("port"))
        if not srv or not port:
            return None
        p = {
            "name": j.get("ps") or f"vmess-{srv}:{port}",
            "type": "vmess",
            "server": srv,
            "port": port,
            "uuid": j.get("id"),
            "alterId": _int(j.get("aid")),
            "cipher": j.get("scy") or "auto",
            "udp": True,
            "skip-cert-verify": True,
        }
        net = (j.get("net") or "tcp").lower()
        if net == "ws":
            p.update({"network": "ws", "ws-opaque": True,
                      "ws-path": j.get("path") or "/",
                      "ws-headers": {"Host": j.get("host") or srv}})
        elif net == "grpc":
            p.update({"network": "grpc", "grpc-service-name": j.get("path") or ""})
        elif net == "h2":
            p.update({"network": "h2", "h2-opts": {"path": j.get("path") or "/"}})
        if str(j.get("tls") or "").lower() in ("tls", "true", "1", "reality"):
            p.update({"tls": True,
                      "servername": j.get("sni") or j.get("host") or srv,
                      "client-fingerprint": "chrome",
                      "alpn": ["http/1.1"]})
        return p

    if scheme in ("vless", "trojan"):
        try:
            main, _, frag = line.partition("#")
            body = main.split("://", 1)[1]
            authority, _, query = body.partition("?")
            cred, _, hostport = authority.rpartition("@")
            if not hostport:
                return None
            host, _, port = hostport.rpartition(":")
            if not host or not port.isdigit():
                return None
            q = _q(query)
            name = urllib.parse.unquote(frag) or f"{scheme}-{host}:{port}"
            p = {"name": name, "type": scheme, "server": host, "port": int(port),
                 "udp": True, "skip-cert-verify": True}
            sec = (q.get("security") or "").lower()
            if scheme == "vless":
                p["uuid"] = urllib.parse.unquote(cred)
                if q.get("flow"):
                    p["flow"] = q["flow"]
                if sec == "reality":
                    p["tls"] = True
                    p["reality-opts"] = {"public-key": q.get("pbk", ""), "short-id": q.get("sid", "")}
                elif sec in ("tls", "xtls"):
                    p["tls"] = True
                p["client-fingerprint"] = q.get("fp") or "chrome"
                p["servername"] = q.get("sni") or q.get("host") or host
                if q.get("alpn"):
                    p["alpn"] = [a for a in urllib.parse.unquote(q["alpn"]).split(",") if a]
            else:
                p["password"] = urllib.parse.unquote(cred)
                if sec == "tls" or q.get("sni"):
                    p["tls"] = True
                p["sni"] = q.get("sni") or q.get("host") or host
            net = (q.get("type") or "tcp").lower()
            if net == "ws":
                p.update({"network": "ws", "ws-opaque": True,
                          "ws-path": q.get("path") or "/",
                          "ws-headers": {"Host": q.get("host") or p.get("servername") or host}})
            elif net == "grpc":
                p.update({"network": "grpc",
                          "grpc-service-name": q.get("servicename") or q.get("serviceName") or ""})
            elif net in ("h2", "http"):
                p.update({"network": "h2", "h2-opts": {"path": q.get("path") or "/",
                                                       "host": [q.get("host") or host]}})
            return p
        except Exception:
            return None

    if scheme == "ss":
        try:
            main, _, frag = line.partition("#")
            body = main[5:]
            if "@" not in body:
                body = b64d(body)
            userinfo, _, hostport = body.rpartition("@")
            if ":" not in userinfo:
                userinfo = b64d(userinfo)
            method, _, password = userinfo.partition(":")
            hostport = hostport.split("/")[0].split("?")[0]
            host, _, port = hostport.rpartition(":")
            if not host or not port.isdigit():
                return None
            return {"name": urllib.parse.unquote(frag) or f"ss-{host}:{port}", "type": "ss",
                    "server": host, "port": int(port), "cipher": method,
                    "password": urllib.parse.unquote(password), "udp": True}
        except Exception:
            return None

    if scheme == "ssr":
        try:
            main, _, frag = line.partition("#")
            raw = b64d(main[6:])
            parts = raw.split(":")
            if len(parts) < 6:
                return None
            host, port, proto, method, obfs, pw_b64 = parts[:6]
            return {"name": urllib.parse.unquote(frag) or f"ssr-{host}:{port}", "type": "ssr",
                    "server": host, "port": int(port), "cipher": method,
                    "password": b64d(pw_b64), "protocol": proto, "obfs": obfs,
                    "udp": True}
        except Exception:
            return None

    # hysteria / hysteria2 / tuic
    try:
        main, _, frag = line.partition("#")
        body = main.split("://", 1)[1]
        authority, _, query = body.partition("?")
        cred, _, hostport = authority.rpartition("@")
        host, _, port = hostport.rpartition(":")
        if not host or not port.isdigit():
            return None
        q = _q(query)
        name = urllib.parse.unquote(frag) or f"{scheme}-{host}:{port}"
        p = {"name": name, "type": scheme, "server": host, "port": int(port),
             "skip-cert-verify": True,
             "sni": q.get("sni") or q.get("peer") or host}
        if scheme == "tuic":
            uuid, _, pw = cred.partition(":")
            p["uuid"], p["password"] = uuid, pw
        else:
            p["password"] = urllib.parse.unquote(cred)
        if q.get("obfs") and scheme == "hysteria2":
            p["obfs"] = q["obfs"]
            if q.get("obfs-password"):
                p["obfs-password"] = q["obfs-password"]
        if q.get("insecure") in ("1", "true"):
            p["skip-cert-verify"] = True
        return p
    except Exception:
        return None


def parse_clash(text: str) -> list[dict]:
    import yaml  # runner 里预装；本地验证时也要求可用

    try:
        doc = yaml.safe_load(text)
    except Exception:
        return []
    if not isinstance(doc, dict):
        return []
    proxies = doc.get("proxies") or []
    out = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        t = str(p.get("type") or "").lower()
        if t not in SUPPORTED:
            continue
        if not p.get("server") or not p.get("port"):
            continue
        p = dict(p)
        p["name"] = str(p.get("name") or f"{t}-{p['server']}:{p['port']}")
        p["port"] = _int(p["port"])
        out.append(p)
    return out


def _usable_host(host: str) -> bool:
    host = (host or "").strip().strip("[]")
    if not host or len(host) > 255:
        return False
    if PRIVATE_HOST_RE.match(host):
        return False
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast:
            return False
    except ValueError:
        pass
    return True


SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "rc4-md5", "chacha20-ietf", "xchacha20",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "none",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}
VMESS_CIPHERS = {"auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"}


def sanitize(p: dict) -> dict | None:
    """把节点整理成 mihomo 一定肯接受的形态；缺关键字段的直接丢弃。

    一个非法 proxy 会让 mihomo 拒绝整份配置，所以在解析阶段就把已知的坑堵掉。
    """
    t = str(p.get("type") or "").lower()
    p = dict(p)
    p.pop("name", None)
    p["port"] = _int(p.get("port"))

    if t in ("vmess", "vless"):
        uid = str(p.get("uuid") or "").strip()
        if len(uid) < 8:
            return None
        p["uuid"] = uid
        if t == "vmess":
            c = str(p.get("cipher") or "auto").lower()
            p["cipher"] = c if c in VMESS_CIPHERS else "auto"
            p["alterId"] = _int(p.get("alterId"))
    elif t == "trojan":
        if not str(p.get("password") or "").strip():
            return None
        p.pop("cipher", None)
    elif t == "ss":
        c = str(p.get("cipher") or "").lower()
        if c not in SS_CIPHERS or not str(p.get("password") or ""):
            return None
        p["cipher"] = c
    elif t == "ssr":
        for k in ("cipher", "password", "protocol", "obfs"):
            if not str(p.get(k) or "").strip():
                return None
    elif t == "hysteria":
        if not str(p.get("password") or "").strip():
            return None
        p.setdefault("up", "50 Mbps")
        p.setdefault("down", "100 Mbps")
        p.setdefault("protocol", "udp")
    elif t == "hysteria2":
        if not str(p.get("password") or "").strip():
            return None
        p.pop("cipher", None)
    elif t == "tuic":
        if not str(p.get("uuid") or "").strip() or not str(p.get("password") or "").strip():
            return None
        p.setdefault("alpn", ["h3"])
        p.pop("cipher", None)
    else:
        return None

    if p.get("network") not in (None, "", "ws", "grpc", "h2", "http", "tcp"):
        p.pop("network", None)
    if p.get("flow") in ("", None):
        p.pop("flow", None)
    for k in ("servername", "sni", "ws-path", "grpc-service-name"):
        if p.get(k) in ("", None):
            p.pop(k, None)
    if isinstance(p.get("ws-headers"), dict) and not p["ws-headers"]:
        p.pop("ws-headers")
    return p


def nodes_from_text(text: str) -> list[dict]:
    """从订阅文本里抽出节点（不做跨源去重）。"""
    nodes: list[dict] = []
    if re.search(r"(?m)^\s*proxies\s*:", text):
        nodes.extend(parse_clash(text))
    if not nodes:
        # 明文 URI 行
        for m in URI_RE.finditer(text):
            end = text.find("\n", m.start())
            line = text[m.start(): end if end > 0 else len(text)]
            p = parse_uri(line)
            if p:
                p["_uri"] = line.strip()
                nodes.append(p)
    if not nodes:
        # 整段 base64
        compact = re.sub(r"\s+", "", text)
        if len(compact) > 100 and re.fullmatch(r"[A-Za-z0-9+/=_\-]+", compact[:5000] or "x"):
            dec = b64d(compact)
            if "://" in dec:
                for m in URI_RE.finditer(dec):
                    end = dec.find("\n", m.start())
                    line = dec[m.start(): end if end > 0 else len(dec)]
                    p = parse_uri(line)
                    if p:
                        p["_uri"] = line.strip()
                        nodes.append(p)
    return nodes


def dedupe(nodes: list[dict]) -> list[dict]:
    seen, out = set(), []
    for raw in nodes:
        p = sanitize(raw)
        if not p:
            continue
        host = str(p.get("server") or "")
        port = _int(p.get("port"))
        if not _usable_host(host) or not (0 < port < 65536):
            continue
        key = (p.get("type"), host, port,
               str(p.get("uuid") or p.get("password") or "")[:32])
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def normalize_names(nodes: list[dict], prefix: str = "n") -> list[dict]:
    """名字必须唯一且不含特殊字符，否则 mihomo 会拒配置。"""
    for i, p in enumerate(nodes, 1):
        p["name"] = f"{prefix}{i:04d}"
    return nodes


def sample(nodes: list[dict], limit: int, seed: str) -> list[dict]:
    if limit <= 0 or len(nodes) <= limit:
        return nodes
    rnd = random.Random(seed)
    return rnd.sample(nodes, limit)


def load_source(url: str, limit: int) -> tuple[list[dict], dict]:
    """抓取并解析一个订阅源，返回 (节点列表, 统计)。"""
    text = http_get(url)
    raw = nodes_from_text(text)
    clean = dedupe(raw)
    picked = sample(clean, limit, url)
    normalize_names(picked)
    stats = {"fetched_bytes": len(text), "parsed": len(raw),
             "unique": len(clean), "sampled": len(picked)}
    return picked, stats
