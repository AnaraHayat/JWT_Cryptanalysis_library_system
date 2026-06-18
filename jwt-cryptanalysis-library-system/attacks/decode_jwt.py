#!/usr/bin/env python3
import base64, sys, json

def b64url_decode(s):
    # pad base64 string
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())

import argparse

parser = argparse.ArgumentParser(description='Decode a JWT header and payload')
parser.add_argument('token', nargs='?', help='JWT token string')
parser.add_argument('--file', '-f', help='Path to file containing the token')
args = parser.parse_args()

token = None
if args.file:
    try:
        token = open(args.file, 'r', encoding='utf-8').read().strip()
    except Exception as e:
        print('Error reading file:', e)
        sys.exit(2)
elif args.token:
    token = args.token
else:
    print('Usage: python attacks/decode_jwt.py <token>    OR    python attacks/decode_jwt.py --file token.txt')
    sys.exit(1)
parts = token.split('.')
if len(parts) < 2:
    print('Invalid token')
    sys.exit(2)

try:
    header = json.loads(b64url_decode(parts[0]).decode())
    payload = json.loads(b64url_decode(parts[1]).decode())
except Exception as e:
    print('Error decoding token:', e)
    sys.exit(3)

print('Header:')
print(json.dumps(header, indent=2))
print('\nPayload:')
print(json.dumps(payload, indent=2))
