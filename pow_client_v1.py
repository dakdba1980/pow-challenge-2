#!/usr/bin/env python3
import ssl
import socket
import hashlib
import secrets
import string
import multiprocessing
import os

# === CONFIGURATION ===
SERVER_HOST = "18.202.148.130"
SERVER_PORT = 3336  # or use one of the others listed
CERT_FILE = "./client-cert.pem"
KEY_FILE = "./client-key.pem"
NAME = "Anil Kumar Dasari"
MAILS = ["dak.dba@gmail.com", "dak.dba@gmail.com"]
SKYPE = "N/A"  # or "N/A"
BIRTHDATE = "11.07.1983"
COUNTRY = "India"
ADDR_LINES = ["Whitefield", "Bengaluru 560066"]
# =====================

ALLOWED_CHARS = ''.join(c for c in string.printable if c not in '\n\r\t ')

def generate_suffix(length=8):
    return ''.join(secrets.choice(ALLOWED_CHARS) for _ in range(length))

def compute_sha1(hex_input):
    return hashlib.sha1(hex_input.encode('utf-8')).hexdigest()

def worker(authdata, difficulty, result_queue, stop_event):
    target_prefix = '0' * int(difficulty)
    while not stop_event.is_set():
        suffix = generate_suffix()
        sha1 = compute_sha1(authdata + suffix)
        if sha1.startswith(target_prefix):
            result_queue.put(suffix)
            stop_event.set()

def find_valid_suffix(authdata, difficulty):
    manager = multiprocessing.Manager()
    result_queue = manager.Queue()
    stop_event = manager.Event()
    pool = []

    for _ in range(os.cpu_count()):
        p = multiprocessing.Process(target=worker, args=(authdata, difficulty, result_queue, stop_event))
        p.start()
        pool.append(p)

    suffix = result_queue.get()
    stop_event.set()
    for p in pool:
        p.terminate()
        p.join()

    return suffix

def tls_connect(host, port, certfile, keyfile):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    raw_sock = socket.create_connection((host, port))
    print(f"🔗 Connected to {host}:{port}")
    return context.wrap_socket(raw_sock, server_hostname=host)

def main():
    conn = tls_connect(SERVER_HOST, SERVER_PORT, CERT_FILE, KEY_FILE)
    f = conn.makefile('rw', buffering=1, newline='\n')
    authdata = ""

    while True:
        line = f.readline()
        if not line:
            break
        args = line.strip().split(' ')
        cmd = args[0]

        if cmd == "HELO":
            f.write("EHLO\n")

        elif cmd == "ERROR":
            print("ERROR:", " ".join(args[1:]))
            break

        elif cmd == "POW":
            authdata, difficulty = args[1], args[2]
            print(f"Solving POW with difficulty {difficulty}...")
            suffix = find_valid_suffix(authdata, int(difficulty))
            print(f"Found suffix: {suffix}")
            f.write(suffix + "\n")

        elif cmd == "END":
            f.write("OK\n")
            print("Application submitted successfully!")
            break

        elif cmd == "NAME":
            token = compute_sha1(authdata + args[1])
            f.write(f"{token} {NAME}\n")

        elif cmd == "MAILNUM":
            token = compute_sha1(authdata + args[1])
            f.write(f"{token} {len(MAILS)}\n")

        elif cmd.startswith("MAIL"):
            index = int(cmd[-1]) - 1
            token = compute_sha1(authdata + args[1])
            f.write(f"{token} {MAILS[index]}\n")

        elif cmd == "SKYPE":
            token = compute_sha1(authdata + args[1])
            f.write(f"{token} {SKYPE}\n")

        elif cmd == "BIRTHDATE":
            token = compute_sha1(authdata + args[1])
            f.write(f"{token} {BIRTHDATE}\n")

        elif cmd == "COUNTRY":
            token = compute_sha1(authdata + args[1])
            f.write(f"{token} {COUNTRY}\n")

        elif cmd == "ADDRNUM":
            token = compute_sha1(authdata + args[1])
            f.write(f"{token} {len(ADDR_LINES)}\n")

        elif cmd.startswith("ADDRLINE"):
            index = int(cmd[-1]) - 1
            token = compute_sha1(authdata + args[1])
            f.write(f"{token} {ADDR_LINES[index]}\n")

    conn.close()

if __name__ == "__main__":
    main()
