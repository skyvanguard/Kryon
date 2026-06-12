"""F202.L exploratorio — raw banner grab + RTSP/HTTP/SSL probe en :7070.
Identifica qué corre en el puerto 7070 cross-host del POC Britimp.
"""

import socket
import ssl

HOSTS = [
    '172.18.201.5',
    '172.18.201.12',
    '172.18.201.15',
    '172.18.201.19',
    '172.18.201.101',
]


def tcp_banner_grab(host: str, port: int = 7070, timeout: float = 3.0) -> str:
    """Connect, send nothing, recv for `timeout`s. Some services emit a
    banner immediately on connect (SSH, FTP, SMTP, RealServer)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.settimeout(2.0)
        data = b''
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 2048:
                    break
        except TimeoutError:
            pass
        s.close()
        return data.decode('utf-8', errors='replace')[:500]
    except Exception as e:
        return f"[ERROR: {type(e).__name__}: {e}]"


def rtsp_options(host: str, port: int = 7070, timeout: float = 3.0) -> str:
    """Send RTSP OPTIONS request — if it's Real Networks RTSP it'll respond."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        req = (
            f"OPTIONS rtsp://{host}:{port} RTSP/1.0\r\n"
            "CSeq: 1\r\n"
            "User-Agent: kryon-probe/1.0\r\n"
            "\r\n"
        )
        s.sendall(req.encode())
        s.settimeout(2.0)
        data = s.recv(4096)
        s.close()
        return data.decode('utf-8', errors='replace')[:500]
    except Exception as e:
        return f"[ERROR: {type(e).__name__}: {e}]"


def http_get(host: str, port: int = 7070, timeout: float = 3.0) -> str:
    """Standard HTTP GET /."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: kryon-probe/1.0\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        s.sendall(req.encode())
        s.settimeout(2.0)
        data = b''
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 4096:
                    break
        except TimeoutError:
            pass
        s.close()
        return data.decode('utf-8', errors='replace')[:600]
    except Exception as e:
        return f"[ERROR: {type(e).__name__}: {e}]"


def tls_handshake(host: str, port: int = 7070, timeout: float = 4.0) -> str:
    """Try TLS handshake; if successful, reveal cert subject."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        ss = ctx.wrap_socket(s, server_hostname=host)
        cert = ss.getpeercert(binary_form=False)
        ss.close()
        return f"TLS handshake OK. Cert subject: {cert.get('subject') if cert else 'N/A'}"
    except ssl.SSLError as e:
        return f"[SSL: {e}]"
    except Exception as e:
        return f"[ERROR: {type(e).__name__}: {e}]"


for host in HOSTS:
    print(f"\n========== {host}:7070 ==========")
    print("--- raw banner grab ---")
    print(tcp_banner_grab(host))
    print("--- HTTP GET / ---")
    print(http_get(host))
    print("--- RTSP OPTIONS ---")
    print(rtsp_options(host))
    print("--- TLS handshake ---")
    print(tls_handshake(host))
