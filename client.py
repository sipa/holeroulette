#!/usr/bin/env python3
"""TCP hole-punching client — connects via rendezvous server, then
performs simultaneous-open and enters bidirectional chat (like nc)."""

import argparse
from datetime import datetime
import json
import os
import re
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


def log_peer_msg(tag, msg):
    ts = datetime.now().strftime("%H:%M:%S.%f")
    print(f'{ts} {tag} Message: "{sanitize(msg)}"', flush=True)


def main():
    ap = argparse.ArgumentParser(description="TCP hole-punching client")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("-4", dest="ipv4", action="store_true", help="IPv4 only")
    g.add_argument("-6", dest="ipv6", action="store_true", help="IPv6 only")
    ap.add_argument("server", help="server address (IPv4, IPv6, or DNS name)")
    ap.add_argument("port", nargs="?", type=int, default=57996)
    args = ap.parse_args()

    server_host = args.server
    server_port = args.port

    if server_host.startswith("[") and server_host.endswith("]"):
        server_host = server_host[1:-1]

    if args.ipv4:
        af = socket.AF_INET
    elif args.ipv6:
        af = socket.AF_INET6
    else:
        af = socket.AF_UNSPEC

    stag = f"SERVER[{server_host}]"

    # ── Phase 1: connect to rendezvous server ───────────────────
    infos = socket.getaddrinfo(server_host, server_port, af,
                               socket.SOCK_STREAM)
    if not infos:
        log(stag, f"Cannot resolve {server_host}")
        sys.exit(1)
    family, stype, proto, _, saddr = infos[0]
    log(stag, f"Resolved {fmt_addr(saddr[0], saddr[1])}")

    sock = socket.socket(family, stype, proto)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        log(stag, "SO_REUSEPORT not available — hole punch may fail")

    bind_ip = "::" if family == socket.AF_INET6 else ""
    sock.bind((bind_ip, 0))
    local_port = sock.getsockname()[1]
    log(stag, f"Local port {local_port}")

    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.connect(saddr)
    log(stag, "Connected to server")

    # ── Phase 2: read server messages until paired ──────────────
    buf = b""
    peer = None

    while True:
        chunk = sock.recv(4096)
        if not chunk:
            log(stag, "Server closed connection")
            if not peer:
                log(stag, "No peer assigned — exiting")
                sys.exit(1)
            break
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            try:
                msg = json.loads(line.decode(errors="replace"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                log(stag, f"Bad server message, skipping: {e}")
                continue
            if msg.get("type") == "welcome":
                log(stag, f"Public address: {fmt_addr(msg['you'][0], msg['you'][1])}")
            elif msg.get("type") == "wait":
                log(stag, "Waiting for a peer...")
            elif msg.get("type") == "punch":
                peer = (msg["peer"][0], msg["peer"][1])
                log(stag, f"Peer assigned: {fmt_addr(peer[0], peer[1])}")
        if peer:
            break

    sock.close()
    log(stag, f"Closed server link — reusing local port {local_port}")

    # ── Phase 3: TCP hole punch ─────────────────────────────────
    peer_ip, peer_port = peer
    if peer_ip.startswith("::ffff:"):
        peer_ip = peer_ip[7:]
    ptag = f"PEER[{peer_ip}]"

    peer_ai = socket.getaddrinfo(peer_ip, peer_port, socket.AF_UNSPEC,
                                 socket.SOCK_STREAM)
    if not peer_ai:
        log(ptag, "Cannot resolve peer address")
        sys.exit(1)
    pfam, ptype, ppro, _, paddr = peer_ai[0]

    winner = [None]
    gate = threading.Lock()
    done = threading.Event()

    time.sleep(0.5)
    log(ptag, "Starting hole punch...")

    def try_connect():
        """Repeated outbound SYN — the simultaneous-open path."""
        bnd = ("::" if pfam == socket.AF_INET6 else "", local_port)
        for i in range(1, 21):
            if done.is_set():
                return
            s = socket.socket(pfam, ptype, ppro)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            try:
                s.bind(bnd)
                s.settimeout(2)
                log(ptag, f"SYN #{i} -> {fmt_addr(peer_ip, peer_port)}")
                s.connect(paddr)
                with gate:
                    if not done.is_set():
                        done.set()
                        winner[0] = s
                        log(ptag, "Outbound connect succeeded!")
                        return
                s.close()
                return
            except (OSError, socket.timeout) as e:
                log(ptag, f"SYN #{i}: {e}")
                s.close()
                time.sleep(0.5)

    def try_listen():
        """Passive listen — fallback if peer's SYN arrives directly."""
        bnd = ("::" if pfam == socket.AF_INET6 else "", local_port)
        ls = socket.socket(pfam, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        try:
            ls.bind(bnd)
            ls.listen(1)
            ls.settimeout(45)
            log(ptag, f"Listening on port {local_port}")
            conn, addr = ls.accept()
            with gate:
                if not done.is_set():
                    done.set()
                    winner[0] = conn
                    log(ptag, f"Inbound connection from {fmt_addr(addr[0], addr[1])}")
                else:
                    conn.close()
        except (OSError, socket.timeout) as e:
            log(ptag, f"Listen: {e}")
        finally:
            try:
                ls.close()
            except OSError:
                pass

    threading.Thread(target=try_connect, daemon=True).start()
    threading.Thread(target=try_listen, daemon=True).start()
    done.wait(timeout=50)

    if not winner[0]:
        log(ptag, "Hole punch FAILED — could not reach peer")
        sys.exit(1)

    peer_sock = winner[0]
    peer_sock.setblocking(True)
    peer_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    log(ptag, "Connected! Entering chat mode (Ctrl-C to quit).")

    # ── Phase 4: bidirectional relay (nc mode) ──────────────────
    def recv_loop():
        partial = ""
        try:
            while True:
                data = peer_sock.recv(4096)
                if not data:
                    break
                text = partial + data.decode(errors="replace")
                *lines, partial = text.split("\n")
                for ln in lines:
                    log_peer_msg(ptag, ln)
            if partial:
                log_peer_msg(ptag, partial)
            log(ptag, "Connection closed by peer")
        except OSError as e:
            log(ptag, f"recv error: {e}")
        os._exit(0)

    threading.Thread(target=recv_loop, daemon=True).start()

    try:
        while True:
            line = sys.stdin.buffer.readline()
            if not line:
                break
            peer_sock.sendall(line)
    except KeyboardInterrupt:
        pass

    log(ptag, "Closing")
    peer_sock.close()


if __name__ == "__main__":
    main()
