#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
"""Check the UEFI TLS client against an independent native OpenSSL 4.1+ server.

Linux only: passes a connected socket descriptor to Tls13Test. Certificate
authentication is deliberately disabled for the temporary self-signed fixture.
"""

import argparse
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time


def handshake(openssl, client, work, case):
    version, group_id, group, cipher_id, cipher = case
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    command = [
        str(openssl), "s_server", "-accept", f"127.0.0.1:{port}",
        "-cert", "cert.pem", "-key", "key.pem", "-groups", group,
        "-www", "-quiet", "-naccept", "1",
    ]
    command += (["-tls1_3", "-ciphersuites", cipher] if version == "0304"
                else ["-tls1_2", "-cipher", cipher])
    logpath = work / f"{version}-{group}-{cipher_id}.log"
    with logpath.open("w") as log:
        server = subprocess.Popen(
            command, cwd=work, stdin=subprocess.DEVNULL,
            stdout=log, stderr=subprocess.STDOUT,
        )
        connection = None
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    raise RuntimeError(logpath.read_text())
                try:
                    connection = socket.create_connection(("127.0.0.1", port), timeout=1)
                    break
                except ConnectionRefusedError:
                    time.sleep(0.05)
            if connection is None:
                raise TimeoutError("Reference server did not become ready")
            connection.setblocking(True)
            for option in [socket.SO_RCVTIMEO, socket.SO_SNDTIMEO]:
                connection.setsockopt(socket.SOL_SOCKET, option, struct.pack("ll", 10, 0))
            result = subprocess.run(
                [str(client), "--interop", str(connection.fileno()),
                 group_id, version, cipher_id],
                cwd=work, pass_fds=(connection.fileno(),),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=30,
            )
            if result.returncode:
                raise RuntimeError(f"UEFI client exited {result.returncode}:\n{result.stdout}")
            line = next((line for line in result.stdout.splitlines()
                         if line.startswith("TLS_INTEROP ")), None)
            expected_group = "secp256r1" if group == "P-256" else group
            protocol = "TLSv1.3" if version == "0304" else "TLSv1.2"
            if (line is None or f"group={expected_group} " not in line
                    or f"cipher={cipher} " not in line
                    or f"protocol={protocol} " not in line):
                raise RuntimeError("Unexpected negotiation:\n" + result.stdout)
            print(line, flush=True)
            connection.close()
            connection = None
            server.wait(timeout=10)
            if server.returncode:
                raise RuntimeError(logpath.read_text())
        finally:
            if connection is not None:
                connection.close()
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", required=True, type=Path)
    parser.add_argument("--client", required=True, type=Path)
    args = parser.parse_args()
    openssl = args.openssl.resolve()
    client = args.client.resolve()
    if sys.platform != "linux":
        parser.error("Linux socket-descriptor transport is required")
    cases = [
        ("0304", group_id, group, cipher_id, cipher)
        for group_id, group in [
            ("17", "P-256"), ("11eb", "SecP256r1MLKEM768"),
            ("11ec", "X25519MLKEM768"), ("11ed", "SecP384r1MLKEM1024"),
        ]
        for cipher_id, cipher in [
            ("1301", "TLS_AES_128_GCM_SHA256"),
            ("1302", "TLS_AES_256_GCM_SHA384"),
        ]
    ]
    cases += [
        ("0303", "17", "P-256", "c02b", "ECDHE-ECDSA-AES128-GCM-SHA256"),
        ("0303", "17", "P-256", "c02c", "ECDHE-ECDSA-AES256-GCM-SHA384"),
    ]
    with tempfile.TemporaryDirectory(prefix="uefi-tls-interop-") as directory:
        work = Path(directory)
        subprocess.run(
            [str(openssl), "req", "-config", "/dev/null", "-x509", "-newkey", "ec",
             "-pkeyopt", "group:P-256", "-noenc", "-subj", "/CN=localhost",
             "-days", "2", "-keyout", "key.pem", "-out", "cert.pem"],
            cwd=work, check=True,
        )
        (work / "key.pem").chmod(0o600)
        for case in cases:
            handshake(openssl, client, work, case)
    print(f"PASS: {len(cases)} external reference handshakes")


if __name__ == "__main__":
    main()
