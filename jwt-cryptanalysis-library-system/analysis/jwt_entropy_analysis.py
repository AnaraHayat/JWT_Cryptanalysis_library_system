#!/usr/bin/env python3
import math, argparse

def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch,0)+1
    entropy = 0.0
    l = len(s)
    for v in freq.values():
        p = v / l
        entropy -= p * math.log2(p)
    return entropy

parser = argparse.ArgumentParser(description='Compute entropy of secrets in a wordlist or single secret')
parser.add_argument('--wordlist', help='Path to wordlist file')
parser.add_argument('--secret', help='Single secret string')
args = parser.parse_args()

if args.secret:
    print('Secret:', args.secret)
    print('Length:', len(args.secret))
    print('Shannon entropy:', shannon_entropy(args.secret))
elif args.wordlist:
    with open(args.wordlist,'r', encoding='utf-8', errors='ignore') as f:
        for i,line in enumerate(f,1):
            s=line.strip()
            if not s: continue
            e=shannon_entropy(s)
            print(f'{i}: len={len(s)} entropy={e:.3f} secret={s}')
else:
    parser.print_help()
