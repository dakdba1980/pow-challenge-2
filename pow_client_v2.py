#!/usr/bin/env python3
import ssl
import socket
import hashlib
import secrets
import string
import multiprocessing
import os
import time

# === CONFIGURATION ===
SERVER_HOST = "18.202.148.130"
SERVER_PORT = 3336
PEM_FILE = "./client.pem"  # <- Single PEM file with both cert and key
NAME = "Anil Kumar Dasari"
MAILS = ["dak.dba@gmail.com", "dak.dba@gmail.com"]
SKYPE = "anil.skype"
BIRTHDATE = "11.07.1980"
COUNTRY = "India"
ADDR_LINES = ["Whitefield", "Bengaluru 560066"]
# =====================

# Allowed characters (printable minus \n \r \t space)
ALLOWED_CHARS = ''.join(c for c in string.printable if c not in '\n\r\t ')

def generate_suffix(length=10):
    return ''.join(secrets.choice(ALLOWED_CHARS) for _ in range(length))

def compute_sha1(hex_input):
    return hashlib.sha1(hex_input.encode('utf-8')).hexdigest()

def worker(authdata, difficulty, result_queue, stop_event):
    target_prefix = '0' * int(difficulty)
    attempts = 0
    while not stop_event.is_set():
        suffix = generate_suffix()
        sha1 = compute_sha1(authdata + suffix)
        attempts += 1
        if attempts % 100_000 == 0:
            print(f"[{multiprocessing.current_process().name}] Attempts: {attempts}")
        if sha1.startswith(target_prefix):
            print(f"[{multiprocessing.current_process().name}] SUCCESS after {attempts} attempts: {suffix}")
            result_queue.put(suffix)
            stop_event.set()
            return

def find_valid_suffix(authdata, difficulty):
    manager = multiprocessing.Manager()
    result_queue = manager.Queue()
    stop_event = manager.Event()
    processes = []

    print(f"Spawning {os.cpu_count()} processes to solve PoW...")
    for _ in range(os.cpu_count()):
        p = multiprocessing.Process(target=worker, args=(authdata, difficulty, result_queue, stop_event))
        p.start()
        processes.append(p)

    suffix = result_queue.get()  # blocks until found
    stop_event.set()

    for p in processes:
        p.terminate()
        p.join()

    return suffix

def tls_connect(host, port, pemfile):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile=pemfile)
    raw_sock = socket.create_connection((host, port))
    return context.wrap_socket(raw_sock, server_hostname=host)

def main():
    print(f"Connecting to {SERVER_HOST}:{SERVER_PORT} using {PEM_FILE}")
    conn = tls_connect(SERVER_HOST, SERVER_PORT, PEM_FILE)
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
            print(f"[+] Received POW challenge. Difficulty: {difficulty}")
            start = time.time()
            suffix = find_valid_suffix(authdata, int(difficulty))
            print(f"[✓] Suffix found: {suffix} in {time.time() - start:.2f}s")
            f.write(suffix + "\n")

        elif cmd == "END":
            f.write("OK\n")
            print("[✓] Application successfully submitted.")
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
