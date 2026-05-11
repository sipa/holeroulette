#!/usr/bin/env python3
"""TCP hole-punching client — connects via rendezvous server, then
performs simultaneous-open and enters bidirectional chat (like nc)."""

import json
import os
import socket
import sys
import threading
import time


def log(tag, msg):
    print(f"[{tag}] {msg}", flush=True)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <server> <port>", file=sys.stderr)
        sys.exit(1)

    server_host = sys.argv[1]
    server_port = int(sys.argv[2])

    if server_host.startswith("[") and server_host.endswith("]"):
        server_host = server_host[1:-1]

    stag = server_host

    # ── Phase 1: connect to rendezvous server ───────────────────
    infos = socket.getaddrinfo(server_host, server_port, socket.AF_UNSPEC,
                               socket.SOCK_STREAM)
    if not infos:
        log(stag, f"Cannot resolve {server_host}")
        sys.exit(1)
    family, stype, proto, _, saddr = infos[0]
    log(stag, f"Resolved {saddr[0]} port {saddr[1]}")

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
            msg = json.loads(line)
            if msg["type"] == "welcome":
                log(stag, f"Public address: {msg['you'][0]}:{msg['you'][1]}")
            elif msg["type"] == "wait":
                log(stag, "Waiting for a peer...")
            elif msg["type"] == "punch":
                peer = (msg["peer"][0], msg["peer"][1])
                log(stag, f"Peer assigned: {peer[0]}:{peer[1]}")
        if peer:
            break

    sock.close()
    log(stag, f"Closed server link — reusing local port {local_port}")

    # ── Phase 3: TCP hole punch ─────────────────────────────────
    peer_ip, peer_port = peer
    if peer_ip.startswith("::ffff:"):
        peer_ip = peer_ip[7:]
    ptag = peer_ip

    peer_ai = socket.getaddrinfo(peer_ip, peer_port, family,
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
                log(ptag, f"SYN #{i} -> {peer_ip}:{peer_port}")
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
                    log(ptag, f"Inbound connection from {addr[0]}:{addr[1]}")
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
                    log(ptag, ln)
            if partial:
                log(ptag, partial)
            log(ptag, "Connection closed by peer")
        except OSError as e:
            log(ptag, f"recv error: {e}")
        os._exit(0)

    threading.Thread(target=recv_loop, daemon=True).start()

    try:
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            peer_sock.sendall(line.encode())
    except KeyboardInterrupt:
        pass

    log(ptag, "Closing")
    peer_sock.close()


if __name__ == "__main__":
    main()
