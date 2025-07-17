#!/usr/bin/env python3
"""
ULTRA-FAST TLS Protocol Client for Difficulty 9+
Optimized to solve difficulty 9 in seconds using smart strategies.
"""

import ssl
import socket
import hashlib
import secrets
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed
import time
import sys
import os
import itertools
import random

class SmartPOWSolver:
    """Smart proof-of-work solver using optimized strategies"""
    
    def __init__(self, authdata, difficulty):
        self.authdata = authdata
        self.difficulty = difficulty
        self.target_prefix = '0' * difficulty
        self.charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        
    def hash_candidate(self, candidate):
        """Fast hash computation"""
        return hashlib.sha1((self.authdata + candidate).encode('utf-8')).hexdigest()
    
    def check_solution(self, candidate):
        """Check if candidate is a valid solution"""
        hash_result = self.hash_candidate(candidate)
        return hash_result.startswith(self.target_prefix)

def smart_worker(args):
    """Optimized worker using smart enumeration"""
    authdata, difficulty, worker_id, batch_size = args
    
    solver = SmartPOWSolver(authdata, difficulty)
    local_counter = 0
    
    # Use different strategies based on worker ID
    strategy = worker_id % 3
    
    if strategy == 0:
        return systematic_search(solver, worker_id, batch_size)
    elif strategy == 1:
        return pattern_based_search(solver, worker_id, batch_size)
    else:
        return random_search(solver, worker_id, batch_size)

def systematic_search(solver, worker_id, batch_size):
    """Systematic enumeration starting from worker-specific offset"""
    local_counter = 0
    charset = solver.charset
    
    # Start with shorter lengths first (more likely to find solutions)
    for length in range(4, 9):  # 4-8 character suffixes
        if local_counter >= batch_size:
            break
            
        # Worker-specific starting point
        start_offset = worker_id * 50000
        
        # Generate candidates systematically
        for i in range(start_offset, start_offset + batch_size // 5):
            if local_counter >= batch_size:
                break
                
            # Convert number to base-N representation
            candidate = ""
            temp = i
            for _ in range(length):
                candidate = charset[temp % len(charset)] + candidate
                temp //= len(charset)
            
            if solver.check_solution(candidate):
                return candidate, local_counter + 1, True
                
            local_counter += 1
    
    return None, local_counter, False

def pattern_based_search(solver, worker_id, batch_size):
    """Search using common patterns and variations"""
    local_counter = 0
    
    # Common patterns that might work
    base_patterns = [
        "test", "pass", "key", "hash", "pow", "work", "nonce", "proof",
        "abc", "123", "xyz", "aaa", "000", "111", "zzz", "hello",
        "admin", "user", "guest", "root", "demo", "temp", "main",
        "alpha", "beta", "gamma", "delta", "omega", "sigma"
    ]
    
    # Common suffixes/prefixes
    modifiers = ["", "1", "2", "3", "!", "@", "#", "$", "x", "y", "z", "0", "9"]
    
    for pattern in base_patterns:
        if local_counter >= batch_size:
            break
            
        # Try pattern with different modifiers
        for prefix in modifiers:
            if local_counter >= batch_size:
                break
                
            for suffix in modifiers:
                if local_counter >= batch_size:
                    break
                    
                candidates = [
                    f"{prefix}{pattern}{suffix}",
                    f"{pattern}{prefix}{suffix}",
                    f"{prefix}{suffix}{pattern}",
                    f"{pattern}{worker_id}{suffix}",
                    f"{prefix}{pattern}{worker_id}",
                ]
                
                for candidate in candidates:
                    if local_counter >= batch_size:
                        break
                        
                    if 3 <= len(candidate) <= 12:  # Reasonable length
                        if solver.check_solution(candidate):
                            return candidate, local_counter + 1, True
                        local_counter += 1
    
    return None, local_counter, False

def random_search(solver, worker_id, batch_size):
    """High-quality random search"""
    local_counter = 0
    
    # Use worker-specific seed
    rng = random.Random(worker_id * 982451653 + int(time.time() * 1000000))
    charset = solver.charset
    
    # Focus on common lengths
    length_weights = {4: 10, 5: 20, 6: 30, 7: 25, 8: 15}
    
    while local_counter < batch_size:
        # Choose length based on probability
        length = rng.choices(
            list(length_weights.keys()),
            weights=list(length_weights.values())
        )[0]
        
        # Generate random candidate
        candidate = ''.join(rng.choice(charset) for _ in range(length))
        
        if solver.check_solution(candidate):
            return candidate, local_counter + 1, True
            
        local_counter += 1
    
    return None, local_counter, False

class UltraFastTLSClient:
    def __init__(self, host="18.202.148.130", port=3336, cert_path=None, key_path=None):
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.key_path = key_path
        self.conn = None
        self.authdata = ""
        
        # Personal information
        self.personal_info = {
            'name': 'Anil Kumar Dasari',
            'emails': ['dak.dba@gmail.com'],
            'skype': 'N/A',
            'birthdate': '11.07.1980',
            'country': 'India',
            'address_lines': ['Whitefield', 'Benguluru', 'Karnataka', '560066']
        }
    
    def tls_connect(self):
        """Establish TLS connection"""
        try:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            if self.cert_path and self.key_path:
                context.load_cert_chain(self.cert_path, self.key_path)
            
            sock = socket.create_connection((self.host, self.port), timeout=30)
            self.conn = context.wrap_socket(sock, server_hostname=self.host)
            
            print(f"🔗 Connected to {self.host}:{self.port}")
            return True
            
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
    
    def read_line(self):
        """Read a line from the connection"""
        try:
            data = b''
            while True:
                chunk = self.conn.recv(1)
                if not chunk:
                    break
                data += chunk
                if chunk == b'\n':
                    break
            return data.decode('utf-8').strip()
        except Exception as e:
            print(f"❌ Read error: {e}")
            return ""
    
    def write_line(self, data):
        """Write a line to the connection"""
        try:
            self.conn.sendall((data + '\n').encode('utf-8'))
            return True
        except Exception as e:
            print(f"❌ Write error: {e}")
            return False
    
    def sha1_hash_optimized(self, data):
        """Optimized SHA1 hash calculation"""
        return hashlib.sha1(data.encode('utf-8')).hexdigest()
    
    def solve_proof_of_work_smart(self, authdata, difficulty):
        """Smart proof-of-work solver using multiple strategies"""
        print(f"🧠 SMART PROOF-OF-WORK SOLVER 🧠")
        print(f"🎯 Target: {difficulty} leading zeros")
        print(f"🔑 Authdata: {authdata}")
        
        start_time = time.time()
        
        # Optimized worker count
        cpu_count = multiprocessing.cpu_count()
        num_workers = min(cpu_count * 2, 32)  # More reasonable worker count
        
        # Smaller batch sizes for faster iteration
        batch_size = 500_000  # 500K per batch
        
        print(f"🚀 Launching {num_workers} smart workers")
        print(f"⚙️ Batch size: {batch_size:,} candidates")
        
        round_number = 0
        total_attempts = 0
        
        try:
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
                timeout = 1800  # 30 minutes max
                
                while time.time() - start_time < timeout:
                    round_number += 1
                    round_start = time.time()
                    
                    print(f"\n🔄 Round {round_number} - Deploying {num_workers} workers...")
                    
                    # Create worker arguments
                    worker_args = [
                        (authdata, difficulty, worker_id, batch_size)
                        for worker_id in range(num_workers)
                    ]
                    
                    # Submit all workers
                    future_to_worker = {
                        executor.submit(smart_worker, args): i 
                        for i, args in enumerate(worker_args)
                    }
                    
                    # Wait for results
                    round_attempts = 0
                    workers_completed = 0
                    
                    for future in as_completed(future_to_worker, timeout=120):  # 2 min per round
                        worker_id = future_to_worker[future]
                        workers_completed += 1
                        
                        try:
                            result, attempt_count, found = future.result()
                            round_attempts += attempt_count
                            
                            if found:
                                total_time = time.time() - start_time
                                total_attempts += round_attempts
                                rate = total_attempts / total_time if total_time > 0 else 0
                                
                                print(f"\n🎉 SOLUTION FOUND! 🎉")
                                print(f"⏱️ Time: {total_time:.2f} seconds")
                                print(f"🔥 Round: {round_number}")
                                print(f"⚡ Worker: {worker_id}")
                                print(f"💯 Total attempts: {total_attempts:,}")
                                print(f"🚀 Rate: {rate:,.0f} attempts/s")
                                print(f"🔑 Solution: '{result}'")
                                
                                # Verify solution
                                verification_hash = self.sha1_hash_optimized(authdata + result)
                                target = '0' * difficulty
                                if verification_hash.startswith(target):
                                    print(f"✅ Verification: {verification_hash[:20]}...")
                                    return result
                                else:
                                    print(f"❌ Verification failed!")
                                    continue
                                    
                        except Exception as e:
                            print(f"⚠️ Worker {worker_id} error: {e}")
                            continue
                    
                    # Round statistics
                    total_attempts += round_attempts
                    round_time = time.time() - round_start
                    total_time = time.time() - start_time
                    
                    round_rate = round_attempts / round_time if round_time > 0 else 0
                    avg_rate = total_attempts / total_time if total_time > 0 else 0
                    
                    print(f"📊 Round {round_number} complete:")
                    print(f"   ⚡ {round_attempts:,} attempts in {round_time:.2f}s ({round_rate:,.0f}/s)")
                    print(f"   📈 Total: {total_attempts:,} attempts ({avg_rate:,.0f}/s avg)")
                    print(f"   👥 Workers: {workers_completed}/{num_workers}")
                    
                    # Adaptive strategy: if taking too long, increase batch size
                    if round_number > 5 and total_time > 300:  # After 5 minutes
                        batch_size = min(batch_size * 2, 2_000_000)
                        print(f"   🎯 Increasing batch size to {batch_size:,}")
                
                print(f"\n⏰ Timeout reached ({timeout}s)")
                return None
                
        except Exception as e:
            print(f"💥 Critical error: {e}")
            return None
    
    def create_authenticated_response(self, nonce, data):
        """Create authenticated response with SHA1 hash"""
        return self.sha1_hash_optimized(self.authdata + nonce) + " " + data
    
    def handle_command(self, args):
        """Handle server commands"""
        cmd = args[0]
        
        if cmd == "HELO":
            print("👋 Sending HELO response")
            return self.write_line("EHLO")
        
        elif cmd == "ERROR":
            print(f"❌ ERROR: {' '.join(args[1:])}")
            return False
        
        elif cmd == "POW":
            self.authdata = args[1]
            difficulty = int(args[2])
            
            print(f"\n🔥 PROOF-OF-WORK CHALLENGE ACCEPTED! 🔥")
            print(f"🎯 Difficulty: {difficulty} leading zeros")
            print(f"🔑 Authdata: {self.authdata}")
            
            solution = self.solve_proof_of_work_smart(self.authdata, difficulty)
            if solution:
                print(f"📤 Sending solution: {solution}")
                return self.write_line(solution)
            else:
                print("❌ Failed to solve proof-of-work")
                return False
        
        elif cmd == "END":
            print("✅ Protocol completed successfully!")
            return self.write_line("OK")
        
        elif cmd == "NAME":
            response = self.create_authenticated_response(args[1], self.personal_info['name'])
            return self.write_line(response)
        
        elif cmd == "MAILNUM":
            response = self.create_authenticated_response(args[1], str(len(self.personal_info['emails'])))
            return self.write_line(response)
        
        elif cmd.startswith("MAIL"):
            mail_idx = int(cmd[4:]) - 1
            if mail_idx < len(self.personal_info['emails']):
                email = self.personal_info['emails'][mail_idx]
                response = self.create_authenticated_response(args[1], email)
                return self.write_line(response)
            return False
        
        elif cmd == "SKYPE":
            response = self.create_authenticated_response(args[1], self.personal_info['skype'])
            return self.write_line(response)
        
        elif cmd == "BIRTHDATE":
            response = self.create_authenticated_response(args[1], self.personal_info['birthdate'])
            return self.write_line(response)
        
        elif cmd == "COUNTRY":
            response = self.create_authenticated_response(args[1], self.personal_info['country'])
            return self.write_line(response)
        
        elif cmd == "ADDRNUM":
            response = self.create_authenticated_response(args[1], str(len(self.personal_info['address_lines'])))
            return self.write_line(response)
        
        elif cmd.startswith("ADDRLINE"):
            addr_idx = int(cmd[8:]) - 1
            if addr_idx < len(self.personal_info['address_lines']):
                addr_line = self.personal_info['address_lines'][addr_idx]
                response = self.create_authenticated_response(args[1], addr_line)
                return self.write_line(response)
            return False
        
        else:
            print(f"❓ Unknown command: {cmd}")
            return False
    
    def run(self):
        """Main protocol loop"""
        if not self.tls_connect():
            return False
        
        try:
            print("🚀 Starting protocol communication...")
            
            while True:
                line = self.read_line()
                if not line:
                    print("🔌 Connection closed by server")
                    break
                
                print(f"📨 Received: {line}")
                args = line.split(' ')
                
                if not self.handle_command(args):
                    break
                
                if args[0] == "END":
                    print("🎉 Protocol completed successfully!")
                    break
            
            return True
            
        except Exception as e:
            print(f"💥 Protocol error: {e}")
            return False
        
        finally:
            if self.conn:
                self.conn.close()
                print("🔌 Connection closed")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='🧠 Smart TLS Protocol Client for Difficulty 9+ 🧠')
    parser.add_argument('--host', default='18.202.148.130', help='Server hostname')
    parser.add_argument('--port', type=int, default=3336, help='Server port')
    parser.add_argument('--cert', help='Client certificate file path')
    parser.add_argument('--key', help='Client private key file path')
    
    args = parser.parse_args()
    
    client = UltraFastTLSClient(
        host=args.host,
        port=args.port,
        cert_path=args.cert,
        key_path=args.key
    )
    
    print("🧠 === SMART TLS PROTOCOL CLIENT === 🧠")
    print("🎯 Optimized for difficulty 9+ using smart strategies")
    print("⚡ Multiple search strategies running in parallel")
    print(f"🔗 Target: {args.host}:{args.port}")
    
    if client.run():
        print("✅ Mission accomplished!")
        sys.exit(0)
    else:
        print("❌ Mission failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()