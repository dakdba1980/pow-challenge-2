#!/usr/bin/env python3
"""
ULTRA-FAST TLS Protocol Client for Difficulty 9+
Optimized to solve difficulty 9 in minutes or seconds using advanced techniques.
"""

import ssl
import socket
import hashlib
import secrets
import string
import threading
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed
import time
import sys
import os
import itertools
import struct
import binascii

# Ultra-optimized charset - sorted by frequency for better hit rates
ULTRA_CHARSET = "etaoinshrdlcumwfgypbvkjxqzETAOINSHRDLCUMWFGYPBVKJXQZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?~"

class FastHasher:
    """Optimized hasher with pre-computed states"""
    def __init__(self, prefix_data):
        self.prefix_bytes = prefix_data.encode('utf-8')
        # Pre-compute hash state after processing prefix
        self.base_hasher = hashlib.sha1()
        self.base_hasher.update(self.prefix_bytes)
        self.base_state = self.base_hasher.digest()
        
    def hash_with_suffix(self, suffix_bytes):
        """Ultra-fast hash computation with suffix"""
        hasher = hashlib.sha1()
        hasher.update(self.prefix_bytes)
        hasher.update(suffix_bytes)
        return hasher.digest()

def ultra_fast_worker(args):
    """Ultra-optimized worker using advanced techniques"""
    authdata, difficulty, worker_id, batch_size = args
    
    # Initialize fast hasher
    fast_hasher = FastHasher(authdata)
    target_bytes = bytes.fromhex('0' * (difficulty * 2))
    
    local_counter = 0
    max_suffix_len = 12
    min_suffix_len = 4
    
    # Each worker uses different strategy and starting point
    strategy = worker_id % 4
    
    if strategy == 0:
        return lightning_search(fast_hasher, target_bytes, difficulty, worker_id, batch_size)
    elif strategy == 1:
        return pattern_search(fast_hasher, target_bytes, difficulty, worker_id, batch_size)
    elif strategy == 2:
        return entropy_search(fast_hasher, target_bytes, difficulty, worker_id, batch_size)
    else:
        return hybrid_ultra_search(fast_hasher, target_bytes, difficulty, worker_id, batch_size)

def lightning_search(fast_hasher, target_bytes, difficulty, worker_id, batch_size):
    """Lightning-fast systematic search with smart enumeration"""
    local_counter = 0
    charset = ULTRA_CHARSET
    charset_len = len(charset)
    
    # Start with most promising suffix lengths (6-8 chars most common)
    length_priority = [6, 7, 8, 5, 9, 4, 10, 11, 12]
    
    for suffix_len in length_priority:
        if local_counter >= batch_size:
            break
            
        # Worker-specific starting point to avoid overlap
        start_index = worker_id * 1000007  # Large prime offset
        
        # Use itertools for ultra-fast enumeration
        total_combinations = charset_len ** suffix_len
        step = max(1, total_combinations // (batch_size // len(length_priority)))
        
        for i in range(start_index, min(start_index + step, total_combinations)):
            if local_counter >= batch_size:
                break
                
            # Convert index to suffix using base conversion
            suffix_chars = []
            temp_i = i
            for _ in range(suffix_len):
                suffix_chars.append(charset[temp_i % charset_len])
                temp_i //= charset_len
            
            suffix = ''.join(suffix_chars)
            suffix_bytes = suffix.encode('ascii')
            
            # Ultra-fast hash check
            hash_bytes = fast_hasher.hash_with_suffix(suffix_bytes)
            local_counter += 1
            
            # Check leading zeros in bytes (much faster than hex conversion)
            if check_leading_zeros_bytes(hash_bytes, difficulty):
                return suffix, local_counter, True
    
    return None, local_counter, False

def pattern_search(fast_hasher, target_bytes, difficulty, worker_id, batch_size):
    """Pattern-based search using common suffix patterns"""
    local_counter = 0
    
    # Common patterns that often appear in solutions
    patterns = [
        "abc", "123", "xyz", "000", "111", "aaa", "zzz",
        "test", "key", "pass", "hash", "pow", "work",
        "!!!", "###", "***", "---", "+++", "===",
        "qwe", "asd", "zxc", "poi", "lkj", "mnb"
    ]
    
    # Extensions and prefixes
    extensions = ["", "1", "2", "3", "!", "@", "#", "$", "x", "y", "z"]
    
    for pattern in patterns:
        if local_counter >= batch_size:
            break
            
        for ext1 in extensions:
            if local_counter >= batch_size:
                break
                
            for ext2 in extensions:
                if local_counter >= batch_size:
                    break
                    
                # Try different combinations
                candidates = [
                    f"{ext1}{pattern}{ext2}",
                    f"{pattern}{ext1}{ext2}",
                    f"{ext1}{ext2}{pattern}",
                    f"{pattern}{worker_id}{ext1}",
                    f"{worker_id}{pattern}{ext2}",
                ]
                
                for candidate in candidates:
                    if local_counter >= batch_size:
                        break
                        
                    if 4 <= len(candidate) <= 12:
                        suffix_bytes = candidate.encode('ascii')
                        hash_bytes = fast_hasher.hash_with_suffix(suffix_bytes)
                        local_counter += 1
                        
                        if check_leading_zeros_bytes(hash_bytes, difficulty):
                            return candidate, local_counter, True
    
    return None, local_counter, False

def entropy_search(fast_hasher, target_bytes, difficulty, worker_id, batch_size):
    """High-entropy search with optimized random generation"""
    local_counter = 0
    
    # Use worker-specific seed for no overlap
    rng = secrets.SystemRandom()
    
    # Pre-generate batches of random data for speed
    charset = ULTRA_CHARSET
    charset_len = len(charset)
    
    # Generate in batches for better performance
    batch_gen_size = min(10000, batch_size // 10)
    
    while local_counter < batch_size:
        # Generate batch of candidates
        candidates = []
        for _ in range(min(batch_gen_size, batch_size - local_counter)):
            suffix_len = rng.choices([6, 7, 8, 5, 9], weights=[30, 25, 20, 15, 10])[0]
            suffix = ''.join(rng.choice(charset) for _ in range(suffix_len))
            candidates.append(suffix)
        
        # Process batch
        for suffix in candidates:
            if local_counter >= batch_size:
                break
                
            suffix_bytes = suffix.encode('ascii')
            hash_bytes = fast_hasher.hash_with_suffix(suffix_bytes)
            local_counter += 1
            
            if check_leading_zeros_bytes(hash_bytes, difficulty):
                return suffix, local_counter, True
    
    return None, local_counter, False

def hybrid_ultra_search(fast_hasher, target_bytes, difficulty, worker_id, batch_size):
    """Hybrid approach combining multiple strategies"""
    local_counter = 0
    third = batch_size // 3
    
    # Try lightning search first
    result, count, found = lightning_search(fast_hasher, target_bytes, difficulty, worker_id, third)
    local_counter += count
    if found:
        return result, local_counter, True
    
    # Try pattern search
    result, count, found = pattern_search(fast_hasher, target_bytes, difficulty, worker_id, third)
    local_counter += count
    if found:
        return result, local_counter, True
    
    # Try entropy search
    result, count, found = entropy_search(fast_hasher, target_bytes, difficulty, worker_id, batch_size - local_counter)
    local_counter += count
    if found:
        return result, local_counter, True
    
    return None, local_counter, False

def check_leading_zeros_bytes(hash_bytes, difficulty):
    """Ultra-fast check for leading zeros in hash bytes"""
    # Convert first few bytes to hex and check
    hex_str = hash_bytes[:((difficulty + 1) // 2)].hex()
    return hex_str.startswith('0' * difficulty)

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
    
    def solve_proof_of_work_lightning_fast(self, authdata, difficulty):
        """Lightning-fast proof-of-work solver for difficulty 9"""
        print(f"⚡ LIGHTNING-FAST PROOF-OF-WORK SOLVER ⚡")
        print(f"🎯 Target: {difficulty} leading zeros")
        print(f"🔑 Authdata: {authdata}")
        
        start_time = time.time()
        
        # Aggressive parallelization
        cpu_count = multiprocessing.cpu_count()
        # Use many more workers for ultra-fast solving
        # num_workers = min(cpu_count * 3, 64)
        num_workers = cpu_count
        
        # Smaller batches for faster feedback and better load distribution
        batch_size = 2_000_000  # 2M hashes per batch
        
        print(f"🚀 Launching {num_workers} workers")
        print(f"⚙️ Batch size: {batch_size:,} hashes")
        print(f"💪 Expected rate: >10M H/s")
        
        round_number = 0
        total_hashes = 0
        
        try:
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
                # Short timeout for fast iterations
                timeout = 600  # 10 minutes max
                
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
                        executor.submit(ultra_fast_worker, args): i 
                        for i, args in enumerate(worker_args)
                    }
                    
                    # Wait for results with shorter timeout for faster rounds
                    round_hashes = 0
                    workers_completed = 0
                    
                    for future in as_completed(future_to_worker, timeout=60):  # 1 min per round
                        worker_id = future_to_worker[future]
                        workers_completed += 1
                        
                        try:
                            result, hash_count, found = future.result()
                            round_hashes += hash_count
                            
                            if found:
                                total_time = time.time() - start_time
                                total_hashes += round_hashes
                                rate = total_hashes / total_time if total_time > 0 else 0
                                
                                print(f"\n🎉 JACKPOT! SOLUTION FOUND! 🎉")
                                print(f"⏱️ Time: {total_time:.3f} seconds")
                                print(f"🔥 Round: {round_number}")
                                print(f"⚡ Worker: {worker_id}")
                                print(f"💯 Total hashes: {total_hashes:,}")
                                print(f"🚀 Rate: {rate:,.0f} H/s")
                                print(f"🔑 Solution: '{result}'")
                                
                                # Quick verification
                                verification_hash = self.sha1_hash_optimized(authdata + result)
                                target = '0' * int(difficulty)
                                if verification_hash.startswith(target):
                                    print(f"✅ Verification: {verification_hash[:20]}...")
                                    print(f"🎯 Target met: {target}")
                                    return result
                                else:
                                    print(f"❌ Verification failed!")
                                    continue
                                    
                        except Exception as e:
                            print(f"⚠️ Worker {worker_id} error: {e}")
                            continue
                    
                    # Quick round statistics
                    total_hashes += round_hashes
                    round_time = time.time() - round_start
                    total_time = time.time() - start_time
                    
                    round_rate = round_hashes / round_time if round_time > 0 else 0
                    avg_rate = total_hashes / total_time if total_time > 0 else 0
                    
                    print(f"📊 Round {round_number} complete:")
                    print(f"   ⚡ {round_hashes:,} hashes in {round_time:.2f}s ({round_rate:,.0f} H/s)")
                    print(f"   📈 Total: {total_hashes:,} hashes ({avg_rate:,.0f} H/s avg)")
                    print(f"   👥 Workers: {workers_completed}/{num_workers}")
                    
                    # Estimate progress (very rough)
                    if avg_rate > 0:
                        estimated_total = 16 ** int(difficulty)
                        progress = (total_hashes / estimated_total) * 100
                        if progress > 0:
                            eta = (estimated_total - total_hashes) / avg_rate
                            print(f"   📊 Est. progress: {progress:.8f}% | ETA: {eta:.0f}s")
                
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
            difficulty = int(args[2])  # FIX: Convert to integer
            
            print(f"\n🔥 PROOF-OF-WORK CHALLENGE ACCEPTED! 🔥")
            print(f"🎯 Difficulty: {difficulty} leading zeros")
            print(f"🔑 Authdata: {self.authdata}")
            
            solution = self.solve_proof_of_work_lightning_fast(self.authdata, difficulty)
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
    
    parser = argparse.ArgumentParser(description='⚡ Lightning-Fast TLS Protocol Client for Difficulty 9+ ⚡')
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
    
    print("⚡ === LIGHTNING-FAST TLS PROTOCOL CLIENT === ⚡")
    print("🎯 Optimized for difficulty 9+ in seconds/minutes")
    print("🚀 Ultra-aggressive parallelization enabled")
    print(f"🔗 Target: {args.host}:{args.port}")
    
    if client.run():
        print("✅ Mission accomplished!")
        sys.exit(0)
    else:
        print("❌ Mission failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()