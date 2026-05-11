#!/usr/bin/env python3
"""TCP hole-punching rendezvous server."""

import json
import math
import random
import select
import socket
import sys
import threading
import time


def normalize_ip(raw_addr):
    """Strip ::ffff: prefix from IPv4-mapped IPv6 addresses."""
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
    if len(sys.argv) > 2:
        print(f"Usage: {sys.argv[0]} [port]", file=sys.stderr)
        sys.exit(1)

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 57996

    try:
        srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        srv.bind(("::", port))
        print(f"Listening on [::]:{port} (dual-stack)")
    except OSError:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("", port))
        print(f"Listening on 0.0.0.0:{port} (IPv4-only)")

    srv.listen(128)
    srv.setblocking(False)

    clients = {}  # fd -> (socket, (ip, port))
    lock = threading.Lock()

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
                    print(f"+ {addr[0]}:{addr[1]}")
                    if send_msg(conn, {"type": "welcome", "you": list(addr)}):
                        with lock:
                            clients[conn.fileno()] = (conn, addr)
                    else:
                        conn.close()
                except OSError as e:
                    print(f"accept error: {e}")

    def match_loop():
        while True:
            time.sleep(10)
            try:
                with lock:
                    n = len(clients)
                    k = math.floor((n + 2) / 4)

                    if n:
                        print(f"pool={n} pairs={k}")

                    items = list(clients.items())
                    random.shuffle(items)

                    paired = set()
                    for i in range(k):
                        fd_a, (sa, aa) = items[2 * i]
                        fd_b, (sb, ab) = items[2 * i + 1]
                        print(f"  {aa[0]}:{aa[1]} <-> {ab[0]}:{ab[1]}")
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
                        s, _ = clients.pop(fd)
                        try:
                            s.close()
                        except OSError:
                            pass

                    dead = []
                    for fd, (s, a) in clients.items():
                        if not send_msg(s, {"type": "wait"}):
                            dead.append(fd)
                    for fd in dead:
                        s, a = clients.pop(fd)
                        print(f"- {a[0]}:{a[1]}")
                        try:
                            s.close()
                        except OSError:
                            pass
            except Exception as e:
                print(f"match error: {e}")

    threading.Thread(target=accept_loop, daemon=True).start()
    threading.Thread(target=match_loop, daemon=True).start()

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nShutting down")


if __name__ == "__main__":
    main()
