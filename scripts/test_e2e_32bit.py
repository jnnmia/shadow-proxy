#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowProxy 32-bit Architecture End-to-End Real Traffic Integration Test.
Verification Pipeline:
1. Local Echo HTTP Server (127.0.0.1:18080)
2. Local Mock SOCKS5 Server (127.0.0.1:11080)
3. 64-bit Master CLI (shadow-cli.exe)
4. 32-bit Dedicated Helper (shadow-injector32.exe)
5. 32-bit Target Process (C:\\Windows\\SysWOW64\\curl.exe)
6. 32-bit Hook DLL (shadow_hook32.dll)
7. Dual-path Traffic Verification:
   - Case A: Domain Fake-IP Transparent Redirection (test32.example.com)
   - Case B: Raw IPv4 Socket Transparent Redirection (1.2.3.4:80)
"""

import os
import sys
import time
import socket
import select
import struct
import threading
import subprocess

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")

HTTP_PORT = 18080
SOCKS5_PORT = 11080

class TestState:
    def __init__(self):
        self.socks5_requests = []
        self.http_requests = []
        self.http_running = True
        self.socks5_running = True

state = TestState()

def run_echo_http_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", HTTP_PORT))
    server.listen(10)
    server.settimeout(1.0)
    print(f"[HTTP] Echo Server listening on 127.0.0.1:{HTTP_PORT}")

    while state.http_running:
        try:
            client, addr = server.accept()
        except socket.timeout:
            continue
        except Exception:
            break

        try:
            data = client.recv(4096).decode("utf-8", errors="ignore")
            if data:
                req_line = data.splitlines()[0] if data.splitlines() else ""
                print(f"[HTTP] Received request: {req_line}")
                state.http_requests.append(req_line)

                if "ip-check" in req_line:
                    body = "SUCCESS_32BIT_IP_TRAFFIC_VERIFIED\n"
                else:
                    body = "SUCCESS_32BIT_DOMAIN_TRAFFIC_VERIFIED\n"

                body_bytes = body.encode("utf-8")
                resp = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/plain\r\n"
                    f"Content-Length: {len(body_bytes)}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode("utf-8") + body_bytes
                client.sendall(resp)
        except Exception as e:
            print(f"[HTTP] Handler error: {e}")
        finally:
            client.close()

    server.close()
    print("[HTTP] Echo Server stopped")

def handle_socks5_client(client):
    try:
        # Step 1: Handshake
        ver, nmethods = client.recv(1), client.recv(1)
        if not ver or ver[0] != 0x05:
            client.close()
            return
        n = nmethods[0]
        methods = client.recv(n)
        # Reply NO AUTH
        client.sendall(b"\x05\x00")

        # Step 2: Request
        req_hdr = client.recv(4)
        if len(req_hdr) < 4 or req_hdr[0] != 0x05 or req_hdr[1] != 0x01:
            client.close()
            return
        atyp = req_hdr[3]
        target_host = ""
        if atyp == 0x01: # IPv4
            ip_raw = client.recv(4)
            target_host = socket.inet_ntoa(ip_raw)
        elif atyp == 0x03: # Domain
            dlen = client.recv(1)[0]
            target_host = client.recv(dlen).decode("latin1", errors="ignore")
        elif atyp == 0x04: # IPv6
            ip_raw = client.recv(16)
            target_host = socket.inet_ntop(socket.AF_INET6, ip_raw)
        port_raw = client.recv(2)
        target_port = struct.unpack("!H", port_raw)[0]

        print(f"[SOCKS5] Handshake success, Target: {target_host}:{target_port}")
        state.socks5_requests.append((target_host, target_port))

        # Reply CONNECT Success
        reply = b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", HTTP_PORT)
        client.sendall(reply)

        # Bridge to local Echo HTTP Server
        backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend.connect(("127.0.0.1", HTTP_PORT))

        sockets = [client, backend]
        while True:
            r, _, _ = select.select(sockets, [], [], 5.0)
            if not r:
                break
            for s in r:
                other = backend if s is client else client
                data = s.recv(8192)
                if not data:
                    return
                other.sendall(data)
    except Exception as e:
        print(f"[SOCKS5] Client error: {e}")
    finally:
        client.close()

def run_socks5_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", SOCKS5_PORT))
    server.listen(10)
    server.settimeout(1.0)
    print(f"[SOCKS5] Mock Server listening on 127.0.0.1:{SOCKS5_PORT}")

    threads = []
    while state.socks5_running:
        try:
            client, addr = server.accept()
        except socket.timeout:
            continue
        except Exception:
            break

        t = threading.Thread(target=handle_socks5_client, args=(client,), daemon=True)
        t.start()
        threads.append(t)

    server.close()
    print("[SOCKS5] Mock Server stopped")

def run_single_e2e_case(case_name, target_url, expected_body):
    print(f"\n--- Running Sub-Test: {case_name} ---")
    cli_exe = os.path.abspath("bin\\shadow-cli.exe")
    curl32_exe = "C:\\Windows\\SysWOW64\\curl.exe"
    output_txt = os.path.abspath(f"bin\\out_{case_name}.txt")

    if os.path.exists(output_txt):
        os.remove(output_txt)

    curl_args = f"-s -S -v -o \"{output_txt}\" {target_url}"
    cmd = [
        cli_exe,
        "--proxy", f"127.0.0.1:{SOCKS5_PORT}",
        "--rules", "global",
        "--target", curl32_exe,
        "--args", curl_args,
    ]

    print(f"[EXEC] Running: {' '.join(cmd)}")
    env = os.environ.copy()
    env["SHADOW_DEBUG"] = "1"

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
        env=env,
    )

    try:
        stdout, stderr = proc.communicate(timeout=15)
        ret = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        ret = -999

    print(f"[STATUS] Process return code: {ret}")
    if stderr:
        print("[STDERR]\n" + stderr)

    curl_output = ""
    if os.path.exists(output_txt):
        with open(output_txt, "r", encoding="utf-8", errors="ignore") as f:
            curl_output = f.read().strip()
        print(f"[CURL OUTPUT] {curl_output}")
        try:
            os.remove(output_txt)
        except Exception:
            pass

    passed = (ret == 0) and (expected_body in curl_output)
    return passed, stdout, stderr

def main():
    print("=== Starting 32-bit Architecture E2E Integration Test Suite ===")

    # Verify components
    cli_exe = os.path.abspath("bin\\shadow-cli.exe")
    helper_exe = os.path.abspath("bin\\shadow-injector32.exe")
    hook32_dll = os.path.abspath("bin\\shadow_hook32.dll")
    curl32_exe = "C:\\Windows\\SysWOW64\\curl.exe"

    for p in [cli_exe, helper_exe, hook32_dll, curl32_exe]:
        if not os.path.exists(p):
            print(f"[ERROR] Missing required component: {p}")
            sys.exit(1)

    print("[INFO] All 32-bit and 64-bit components verified.")

    # Start background servers
    http_thread = threading.Thread(target=run_echo_http_server, daemon=True)
    http_thread.start()

    socks5_thread = threading.Thread(target=run_socks5_server, daemon=True)
    socks5_thread.start()

    time.sleep(0.5)

    assertions = []

    # Case A: Domain Fake-IP
    pass_a, stdout_a, _ = run_single_e2e_case(
        "case_domain",
        "http://test32.example.com/domain-check",
        "SUCCESS_32BIT_DOMAIN_TRAFFIC_VERIFIED"
    )
    assertions.append(("Case A (Domain Fake-IP Redirection)", pass_a))
    assertions.append(("Case A 32-bit Architecture Dispatched", "X86" in stdout_a and "32 位专用注入模块执行完成" in stdout_a))
    has_domain = any("test32.example.com" in str(req[0]) for req in state.socks5_requests)
    assertions.append(("Case A SOCKS5 Received Domain Target", has_domain))

    # Case B: Raw IPv4 Socket
    pass_b, stdout_b, _ = run_single_e2e_case(
        "case_raw_ip",
        "http://1.2.3.4:80/ip-check",
        "SUCCESS_32BIT_IP_TRAFFIC_VERIFIED"
    )
    assertions.append(("Case B (Raw IPv4 Transparent Redirection)", pass_b))
    assertions.append(("Case B 32-bit Architecture Dispatched", "X86" in stdout_b and "32 位专用注入模块执行完成" in stdout_b))
    has_ip = any("1.2.3.4" in str(req[0]) for req in state.socks5_requests)
    assertions.append(("Case B SOCKS5 Received IPv4 Target", has_ip))

    # Stop servers
    state.http_running = False
    state.socks5_running = False

    print("\n=== Final Test Results Matrix ===")
    all_passed = True
    for desc, passed in assertions:
        status_str = "PASS" if passed else "FAIL"
        print(f"- [{status_str}] {desc}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\nAll 32-bit dual-path E2E integration assertions PASSED successfully!")
        sys.exit(0)
    else:
        print("\nOne or more assertions FAILED!")
        sys.exit(1)

if __name__ == "__main__":
    main()
