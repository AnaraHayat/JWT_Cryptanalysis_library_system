#!/usr/bin/env python3
import requests, time, argparse, statistics

parser = argparse.ArgumentParser(description='Basic timing probe against a protected endpoint')
parser.add_argument('--url', required=True, help='Protected endpoint URL')
parser.add_argument('--token', required=True, help='Authorization Bearer token to test')
parser.add_argument('--samples', type=int, default=100, help='Number of samples')
args = parser.parse_args()

headers = {'Authorization': 'Bearer ' + args.token}

times = []
for i in range(args.samples):
    t0 = time.perf_counter()
    r = requests.get(args.url, headers=headers)
    t1 = time.perf_counter()
    times.append((t1-t0)*1000)
    if i%20==0:
        print(f'sample {i}: status={r.status_code} time={(t1-t0)*1000:.2f}ms')

print('\nSummary (ms):')
print('count', len(times))
print('mean', statistics.mean(times))
print('stdev', statistics.pstdev(times))
print('min', min(times), 'max', max(times))
