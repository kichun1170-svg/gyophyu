#!/usr/bin/env python3
"""Fetch public free V2Ray/VLESS configs, dedupe, optional TCP reachability test,
and publish subscription files (plain + base64) for V2RayNG / NekoBox / Hiddify.

Standard library only — no pip installs needed (works in GitHub Actions as-is).
Failed sources are skipped gracefully, so the run never dies because one source
changed or is unreachable.
"""

import base64
import concurrent.futures
import json
import os
import socket
import sys
import urllib.request

SOURCES = [
    # --- verified working (2026-11-22) ---
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://cdn.jsdelivr.net/gh/mahdibland/V2RayAggregator@master/sub/sub_merge.txt",
    # --- best-effort: exists on GitHub (per jsDelivr index) even though 404/blocked from some networks;
    #     GitHub Actions runners usually fetch it fine ---
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
]

SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) sub-aggregator/1.0"}
FETCH_TIMEOUT = 25
TCP_TIMEOUT = 2.5
TEST_CAP = 3000  # only TCP-test the first N deduped configs (keep runtime sane on Actions)


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        return resp.read()


def maybe_b64decode(text: str) -> str:
    """If the body is a base64-encoded subscription, decode it; otherwise return as-is."""
    text = text.strip()
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            data = decoder(text + "====", validate=False)
            decoded = data.decode("utf-8", errors="ignore")
            if any(decoded.lstrip().startswith(s) for s in SCHEMES):
                return decoded
        except Exception:
            pass
    return text


def is_valid(line: str) -> bool:
    if len(line) < 12 or line.count("://") != 1:
        return False
    return line.startswith(SCHEMES)


def _decode_vmess(rest: str):
    body = rest.split("#", 1)[0]
    pad = "=" * (-len(body) % 4)
    return json.loads(base64.b64decode(body + pad).decode("utf-8", errors="ignore"))


def canonical_key(line: str):
    scheme, rest = line.split("://", 1)
    if scheme == "vmess":
        try:
            obj = _decode_vmess(rest)
            return ("vmess", str(obj.get("add", "")).lower(), str(obj.get("port", "")), str(obj.get("id", "")))
        except Exception:
            return (line,)
    main = rest.split("#", 1)[0].split("?", 1)[0]
    if "@" in main:
        userinfo, hostport = main.rsplit("@", 1)
    else:
        userinfo, hostport = "", main
    return (scheme, hostport.lower(), userinfo)


def host_port(line: str):
    scheme, rest = line.split("://", 1)
    if scheme == "vmess":
        try:
            obj = _decode_vmess(rest)
            host = str(obj.get("add", "")).strip("[]")
            return (host, int(obj.get("port", 0) or 0))
        except Exception:
            return None
    main = rest.split("#", 1)[0].split("?", 1)[0]
    if "@" in main:
        main = main.rsplit("@", 1)[1]
    main = main.split("/", 1)[0]
    if main.startswith("["):  # [ipv6]:port
        host, _, port = main[1:].partition("]")
        port = port.lstrip(":")
    else:
        host, _, port = main.rpartition(":")
    try:
        return (host, int(port))
    except Exception:
        return None


def tcp_ok(hp, timeout=TCP_TIMEOUT) -> bool:
    try:
        host, port = hp
        if not host or not port:
            return False
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        family, socktype, proto, _, addr = infos[0]
        with socket.create_connection(addr, timeout=timeout):
            return True
    except Exception:
        return False


def main() -> None:
    args = sys.argv[1:]
    out_dir = args[0] if args and not args[0].startswith("--") else "sub"
    do_test = "--no-test" not in args
    os.makedirs(out_dir, exist_ok=True)

    raw_lines = []
    for src in SOURCES:
        try:
            body = fetch(src).decode("utf-8", errors="ignore")
        except Exception as exc:
            print(f"[skip] {src} -> {type(exc).__name__}")
            continue
        decoded = maybe_b64decode(body)
        n = 0
        for line in decoded.splitlines():
            line = line.strip()
            if is_valid(line):
                raw_lines.append(line)
                n += 1
        print(f"[ok]   {src} -> {n} configs")

    print(f"total raw lines kept: {len(raw_lines)}")

    seen, unique = set(), []
    for line in raw_lines:
        key = canonical_key(line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(line)
    print(f"unique: {len(unique)}")

    if do_test and unique:
        head, rest = unique[:TEST_CAP], unique[TEST_CAP:]
        alive = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=256) as pool:
            futures = {pool.submit(tcp_ok, host_port(line)): line for line in head}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    if fut.result():
                        alive.append(futures[fut])
                except Exception:
                    pass
        print(f"tcp-tested: {len(head)}, alive: {len(alive)} (untested tail kept: {len(rest)})")
        if alive:
            unique = alive + rest  # fail-open: if nothing connects, keep everything

    by_proto = {}
    for line in unique:
        proto = line.split("://", 1)[0].replace("hy2://", "hysteria2://")
        by_proto.setdefault(proto, []).append(line)

    def write(name: str, lines) -> None:
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        b64 = base64.b64encode("\n".join(lines).encode()).decode()
        with open(os.path.join(out_dir, name.replace(".txt", "_b64.txt")), "w", encoding="utf-8") as f:
            f.write(b64)

    write("all.txt", unique)
    for proto, lines in sorted(by_proto.items()):
        write(f"{proto}.txt", lines)

    # Amnezia-friendly output: VLESS + Reality only (most censorship-resistant)
    reality = [l for l in unique if l.startswith("vless://") and "security=reality" in l]
    if reality:
        write("vless_reality.txt", reality)
        print(f"vless reality-only: {len(reality)}")

    print(f"WROTE {out_dir} (all={len(unique)}, protocols={sorted(by_proto)})")


if __name__ == "__main__":
    main()
