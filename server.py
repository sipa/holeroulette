#!/usr/bin/env python3
"""TCP hole-punching rendezvous server."""

import argparse
from collections import defaultdict
from datetime import datetime
import json
import math
import random
import re
import select
import socket
import sys
import threading
import time

_CTRL_RE = re.compile(r'[\x00-\x1f\x7f-\x9f]')


def sanitize(s):
    return _CTRL_RE.sub('', str(s))


def fmt_addr(ip, port):
    ip = sanitize(str(ip))
    if ':' in ip:
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def log(tag, msg):
    ts = datetime.now().strftime("%H:%M:%S.%f")
    print(f"{ts} {tag} {sanitize(msg)}", flush=True)


def normalize_ip(raw_addr):
    ip, port = raw_addr[0], raw_addr[1]
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip, port


def send_msg(sock, obj):
    try:
        sock.sendall((json.dumps(obj) + "\n").encode())
        return True
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser(description="TCP hole-punching rendezvous server")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("-4", dest="ipv4", action="store_true", help="IPv4 only")
    g.add_argument("-6", dest="ipv6", action="store_true", help="IPv6 only")
    ap.add_argument("port", nargs="?", type=int, default=57996)
    args = ap.parse_args()

    port = args.port

    ltag = "LISTEN"

    if args.ipv4:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("", port))
        log(ltag, f"0.0.0.0:{port} (IPv4)")
    elif args.ipv6:
        srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        srv.bind(("::", port))
        log(ltag, f"[::]:{port} (IPv6)")
    else:
        try:
            srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            srv.bind(("::", port))
            log(ltag, f"[::]:{port} (dual-stack)")
        except OSError:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("", port))
            log(ltag, f"0.0.0.0:{port} (IPv4-only fallback)")

    srv.listen(128)
    srv.setblocking(False)

    pool4 = {}  # fd -> (socket, (ip, port))  — IPv4 clients
    pool6 = {}  # fd -> (socket, (ip, port))  — IPv6 clients
    lock = threading.Lock()

    def is_ipv6(ip):
        return ":" in ip

    def accept_loop():
        while True:
            try:
                rd, _, _ = select.select([srv], [], [], 1.0)
            except (OSError, ValueError):
                break
            for _ in rd:
                try:
                    conn, raw = srv.accept()
                    conn.setblocking(True)
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    addr = normalize_ip(raw)
                    pool = pool6 if is_ipv6(addr[0]) else pool4
                    ctag = f"CLIENT[{fmt_addr(addr[0], addr[1])}]"
                    ver = "v6" if is_ipv6(addr[0]) else "v4"
                    log(ctag, f"Connected ({ver})")
                    if send_msg(conn, {"type": "welcome", "you": list(addr)}):
                        with lock:
                            pool[conn.fileno()] = (conn, addr)
                    else:
                        conn.close()
                except OSError as e:
                    log(ltag, f"accept error: {e}")

    def match_pool(pool, ver):
        """Run one matching round on a single pool. Called with lock held."""
        n = len(pool)
        k = math.floor((n + 2) / 4)
        ptag = f"POOL[{ver}]"

        if n:
            log(ptag, f"pool={n} pairs={k}")

        by_ip = defaultdict(list)
        for fd, (s, a) in pool.items():
            by_ip[a[0]].append((fd, s, a))
        for g in by_ip.values():
            random.shuffle(g)

        paired = set()
        for _ in range(k):
            groups = sorted(
                (g for g in by_ip.values() if g),
                key=len, reverse=True,
            )
            if len(groups) < 2:
                break
            fd_a, sa, aa = groups[0].pop()
            fd_b, sb, ab = groups[1].pop()
            log(ptag, f"Pair {fmt_addr(aa[0], aa[1])} <-> {fmt_addr(ab[0], ab[1])}")
            send_msg(sa, {"type": "punch", "peer": list(ab)})
            send_msg(sb, {"type": "punch", "peer": list(aa)})
            for s in (sa, sb):
                try:
                    s.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            paired.add(fd_a)
            paired.add(fd_b)

        for fd in paired:
            s, _ = pool.pop(fd)
            try:
                s.close()
            except OSError:
                pass

        dead = []
        for fd, (s, a) in pool.items():
            if not send_msg(s, {"type": "wait"}):
                dead.append(fd)
        for fd in dead:
            s, a = pool.pop(fd)
            log(f"CLIENT[{fmt_addr(a[0], a[1])}]", "Dropped")
            try:
                s.close()
            except OSError:
                pass

    def match_loop():
        while True:
            time.sleep(10)
            try:
                with lock:
                    match_pool(pool4, "v4")
                    match_pool(pool6, "v6")
            except Exception as e:
                log("MATCH", f"error: {e}")

    threading.Thread(target=accept_loop, daemon=True).start()
    threading.Thread(target=match_loop, daemon=True).start()

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        log(ltag, "Shutting down")


if __name__ == "__main__":
    main()
