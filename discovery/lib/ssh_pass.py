"""Run one command over SSH with a password, for when sshpass is not installed.

    SSHPASS=... python3 ssh_pass.py -p PORT -k KNOWN_HOSTS USER@HOST COMMAND

Behaves like `sshpass -e ssh -o StrictHostKeyChecking=accept-new
-o UserKnownHostsFile=KNOWN_HOSTS ...` as scan_auth.sh uses it: the password
comes from $SSHPASS (never argv), a new host key is added to KNOWN_HOSTS, a
changed one stops before the password is sent. Output (stdout + stderr) goes
to stdout. Exit code: the remote command's, 5 = login refused (as sshpass),
255 = connection or host-key problem (as ssh).
"""
from __future__ import annotations

import argparse
import os
import socket
import sys

import paramiko


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--port", type=int, default=22)
    ap.add_argument("-k", "--known-hosts", required=True)
    ap.add_argument("-t", "--timeout", type=float, default=6)
    ap.add_argument("dest")
    ap.add_argument("command")
    a = ap.parse_args()
    user, _, host = a.dest.rpartition("@")
    password = os.environ.pop("SSHPASS", "")
    if not user or not host:
        print("usage: user@host", file=sys.stderr)
        return 255

    try:
        sock = socket.create_connection((host, a.port), timeout=a.timeout)
    except OSError as e:
        print(f"ssh: connect to host {host} port {a.port}: {e.strerror or e}")
        return 255
    t = paramiko.Transport(sock)
    try:
        t.start_client(timeout=20)
        key = t.get_remote_server_key()
        name = host if a.port == 22 else f"[{host}]:{a.port}"
        known = paramiko.HostKeys()
        if os.path.exists(a.known_hosts):
            known.load(a.known_hosts)
        have = known.lookup(name)
        if have is not None and key.get_name() in have:
            if have[key.get_name()].asbytes() != key.asbytes():
                print("@@@ REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.")
                return 255
        else:                                   # accept-new: remember it
            os.makedirs(os.path.dirname(os.path.abspath(a.known_hosts)), exist_ok=True)
            with open(a.known_hosts, "a") as fh:
                fh.write(f"{name} {key.get_name()} {key.get_base64()}\n")
        try:
            t.auth_password(user, password)
        except paramiko.BadAuthenticationType:
            print(f"{user}@{host}: Permission denied (password login not allowed)")
            return 5
        except paramiko.AuthenticationException:
            print(f"{user}@{host}: Permission denied (wrong user name or password)")
            return 5
        finally:
            password = ""
        ch = t.open_session(timeout=15)
        ch.set_combine_stderr(True)
        ch.exec_command(a.command)
        out = sys.stdout.buffer
        while True:
            data = ch.recv(65536)
            if not data:
                break
            out.write(data)
        out.flush()
        return ch.recv_exit_status()
    except (paramiko.SSHException, EOFError, OSError) as e:
        print(f"ssh: {host}: {e or 'connection closed'}")
        return 255
    finally:
        t.close()


if __name__ == "__main__":
    sys.exit(main())
