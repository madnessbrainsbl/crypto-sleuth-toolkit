#!/usr/bin/env python3
import jwt
import hmac
import hashlib
import itertools
import sys

# Working JWT token
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

# Decode without verification to get payload
header = jwt.get_unverified_header(WORKING_TOKEN)
payload = jwt.decode(WORKING_TOKEN, options={"verify_signature": False})

print("Header:", header)
print("Payload:", payload)

# Common strings that might be part of the key
base_candidates = [
    "CunBA",
    "unlock", 
    "secret",
    "key",
    "mega",
    "huron",
    "qnx",
    "0d79ff047f5cec5bf2ec2ec7d3e464ce",  # vehicle_id
    str(payload['timestamp']),
    "1753096202",
    "cunba_unlock",
    "mega_unlock",
    "huron_unlock"
]

# Common prefixes/suffixes
prefixes = ["", "mega_", "huron_", "qnx_", "unlock_"]
suffixes = ["", "_key", "_secret", "_hmac", "_jwt"]

# Generate combinations
candidates = []
for base in base_candidates:
    for prefix in prefixes:
        for suffix in suffixes:
            candidates.append(prefix + base + suffix)
            candidates.append((prefix + base + suffix).upper())
            candidates.append((prefix + base + suffix).lower())

# Also try hashes of common strings
for candidate in list(candidates):
    # MD5
    candidates.append(hashlib.md5(candidate.encode()).hexdigest())
    # SHA256
    candidates.append(hashlib.sha256(candidate.encode()).hexdigest())
    # SHA1
    candidates.append(hashlib.sha1(candidate.encode()).hexdigest())

# Remove duplicates
candidates = list(set(candidates))

print(f"\nTrying {len(candidates)} key candidates...")

# Try each candidate
found = False
for i, key_candidate in enumerate(candidates):
    if i % 100 == 0:
        print(f"Progress: {i}/{len(candidates)}")
    
    try:
        # Try decoding with this key
        decoded = jwt.decode(WORKING_TOKEN, key_candidate, algorithms=["HS256"])
        print(f"\n✅ FOUND KEY: '{key_candidate}'")
        print(f"Decoded payload: {decoded}")
        found = True
        break
    except:
        continue

if not found:
    print("\n❌ Key not found in common combinations")
    print("\nNext steps:")
    print("1. Look for strings in the binary near crypto functions")
    print("2. Check memory dumps during token validation")
    print("3. Analyze the specific crypto functions in detail")

# Also create a function to test custom keys
def test_key(key):
    try:
        decoded = jwt.decode(WORKING_TOKEN, key, algorithms=["HS256"])
        print(f"✅ Valid key: '{key}'")
        return True
    except:
        return False

# Save candidates for later testing
with open("D:\\vz\\key_candidates.txt", "w") as f:
    for c in candidates:
        f.write(c + "\n")

print(f"\nSaved {len(candidates)} candidates to key_candidates.txt")
