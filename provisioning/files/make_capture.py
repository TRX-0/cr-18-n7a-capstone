#!/usr/bin/env python3
"""
N7a - Capstone  :  handover capture generator
Orion Retail Ltd / CyberRangeCZ training node

Builds orion-handover.pcapng: the capture Orion's SOC hands the tester at the
start of the engagement. One HTTP session to the operations panel on web01,
authenticated with Basic auth over plain HTTP, so the credential crosses the
wire in a form anyone on-path can read.

No third-party modules - the pcapng and every frame are assembled by hand so
this runs on a stock Python.

    python3 make_capture.py            # writes orion-handover.pcapng
"""
import base64
import struct
import sys

# ---------------------------------------------------------------- lab config
CLIENT_IP = "192.168.60.45"          # the ops laptop; not part of the sandbox
SERVER_IP = "192.168.60.20"          # web01
CLIENT_MAC = "3c:97:0e:b4:71:2a"
SERVER_MAC = "00:16:3e:5a:0c:19"
CLIENT_PORT = 51544
SERVER_PORT = 80

PANEL_USER = "webops"
PANEL_PASS = "Or10n_Rem3d1at3d!"
REALM = "Orion Operations"

# 2026-10-12 08:41:03 UTC - the pre-engagement window, a fortnight after the
# second intrusion the trainee reviewed in N6b.
BASE_TS = 1791880863.114205
OUT = "orion-handover.pcapng"


# ---------------------------------------------------------------- frame build
def mac(s):
    return bytes.fromhex(s.replace(":", ""))


def ip4(s):
    return bytes(int(o) for o in s.split("."))


def ones_complement(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_segment(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b"",
                window=64240):
    offset_flags = (5 << 12) | flags          # 20-byte header, no options
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags,
                      window, 0, 0)
    pseudo = ip4(src_ip) + ip4(dst_ip) + struct.pack("!BBH", 0, 6,
                                                     len(hdr) + len(payload))
    csum = ones_complement(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack("!H", csum) + hdr[18:]
    return hdr + payload


def ipv4_packet(src_ip, dst_ip, ident, payload):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, ident, 0x4000, 64, 6, 0)
    hdr += ip4(src_ip) + ip4(dst_ip)
    csum = ones_complement(hdr)
    hdr = hdr[:10] + struct.pack("!H", csum) + hdr[12:]
    return hdr + payload


def ethernet(dst_mac, src_mac, ethertype, payload):
    return mac(dst_mac) + mac(src_mac) + struct.pack("!H", ethertype) + payload


def arp(op, sender_mac, sender_ip, target_mac, target_ip):
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + \
        mac(sender_mac) + ip4(sender_ip) + mac(target_mac) + ip4(target_ip)


# ---------------------------------------------------------------- pcapng
def block(btype, body):
    total = 12 + len(body) + (-len(body) % 4)
    return struct.pack("<II", btype, total) + body + \
        b"\x00" * (-len(body) % 4) + struct.pack("<I", total)


def shb():
    body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    return block(0x0A0D0D0A, body)


def idb(linktype=1, snaplen=262144):
    return block(0x00000001, struct.pack("<HHI", linktype, 0, snaplen))


def epb(frame, ts):
    usec = int(round(ts * 1000000))
    body = struct.pack("<IIIII", 0, usec >> 32, usec & 0xFFFFFFFF,
                       len(frame), len(frame)) + frame
    pad = -len(frame) % 4
    total = 12 + 20 + len(frame) + pad
    return struct.pack("<II", 0x00000006, total) + body + b"\x00" * pad + \
        struct.pack("<I", total)


# ---------------------------------------------------------------- the session
def main():
    creds = base64.b64encode(
        (PANEL_USER + ":" + PANEL_PASS).encode()).decode()

    unauth_req = (
        "GET /admin/ HTTP/1.1\r\n"
        "Host: ops.orion.local\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n"
        "Accept: text/html\r\n"
        "Connection: keep-alive\r\n\r\n"
    ).encode()

    challenge_body = (
        "<html><head><title>401 Unauthorized</title></head>\n"
        "<body><h1>Authorization Required</h1></body></html>\n"
    )
    challenge = (
        "HTTP/1.1 401 Unauthorized\r\n"
        "Server: nginx\r\n"
        'WWW-Authenticate: Basic realm="' + REALM + '"\r\n'
        "Content-Type: text/html\r\n"
        "Content-Length: " + str(len(challenge_body)) + "\r\n"
        "Connection: keep-alive\r\n\r\n" + challenge_body
    )

    auth_req = (
        "GET /admin/ HTTP/1.1\r\n"
        "Host: ops.orion.local\r\n"
        "Authorization: Basic " + creds + "\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n"
        "Accept: text/html\r\n"
        "Connection: keep-alive\r\n\r\n"
    )

    ok_body = (
        "<html><head><title>Orion Operations</title></head>\n"
        "<body>\n<h2>Operations Panel</h2>\n"
        "<p>Signed in as webops.</p>\n"
        "<ul><li>Backup schedule</li><li>Transfer log</li></ul>\n"
        "</body></html>\n"
    )
    ok = (
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: " + str(len(ok_body)) + "\r\n"
        "Connection: keep-alive\r\n\r\n" + ok_body
    )

    state = {"ident": 41000}
    frames = []

    def push(dt, src_mac, dst_mac, src_ip, dst_ip, sport, dport,
             seq, ack, flags, payload=b""):
        state["ident"] += 1
        seg = tcp_segment(src_ip, dst_ip, sport, dport, seq, ack, flags,
                          payload)
        pkt = ipv4_packet(src_ip, dst_ip, state["ident"], seg)
        frames.append((BASE_TS + dt, ethernet(dst_mac, src_mac, 0x0800, pkt)))

    # who-has web01 - the ops laptop resolving the server before connecting
    frames.append((BASE_TS - 0.004120, ethernet(
        "ff:ff:ff:ff:ff:ff", CLIENT_MAC, 0x0806,
        arp(1, CLIENT_MAC, CLIENT_IP, "00:00:00:00:00:00", SERVER_IP))))
    frames.append((BASE_TS - 0.003733, ethernet(
        CLIENT_MAC, SERVER_MAC, 0x0806,
        arp(2, SERVER_MAC, SERVER_IP, CLIENT_MAC, CLIENT_IP))))

    cseq, sseq = 1041558201, 3882104776

    push(0.000000, CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP,
         CLIENT_PORT, SERVER_PORT, cseq, 0, 0x02)                  # SYN
    push(0.000311, SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP,
         SERVER_PORT, CLIENT_PORT, sseq, cseq + 1, 0x12)           # SYN,ACK
    cseq += 1
    sseq += 1
    push(0.000404, CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP,
         CLIENT_PORT, SERVER_PORT, cseq, sseq, 0x10)               # ACK

    push(0.000522, CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP,
         CLIENT_PORT, SERVER_PORT, cseq, sseq, 0x18, unauth_req)
    cseq += len(unauth_req)
    push(0.001887, SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP,
         SERVER_PORT, CLIENT_PORT, sseq, cseq, 0x18, challenge.encode())
    sseq += len(challenge)

    push(0.083104, CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP,
         CLIENT_PORT, SERVER_PORT, cseq, sseq, 0x18, auth_req.encode())
    cseq += len(auth_req)
    push(0.085660, SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP,
         SERVER_PORT, CLIENT_PORT, sseq, cseq, 0x18, ok.encode())
    sseq += len(ok)

    push(0.140233, CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP,
         CLIENT_PORT, SERVER_PORT, cseq, sseq, 0x11)               # FIN,ACK
    cseq += 1
    push(0.140690, SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP,
         SERVER_PORT, CLIENT_PORT, sseq, cseq, 0x11)               # FIN,ACK
    sseq += 1
    push(0.140805, CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP,
         CLIENT_PORT, SERVER_PORT, cseq, sseq, 0x10)               # ACK

    out = shb() + idb()
    for ts, frame in sorted(frames, key=lambda f: f[0]):
        out += epb(frame, ts)

    with open(OUT, "wb") as fh:
        fh.write(out)

    print(OUT + "  " + str(len(out)) + " bytes, " + str(len(frames)) +
          " frames")
    print("credential on the wire: " + PANEL_USER + " / " + PANEL_PASS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
