Quick attack & analysis helpers for the IS Project JWT demo

Usage examples (from repository root `jwt-cryptanalysis-library-system`):

# Install Python deps
pip install -r requirements.txt

# Forge alg:none token
python attacks/forge_none.py --username attacker --role Admin

# Brute-force HMAC secret (requires token)
python attacks/brute_force_hmac.py <HS256_TOKEN> --wordlist secrets/wordlist.txt

# Timing probe
python attacks/timing_attack.py --url http://localhost:5000/api/books-protected --token <TOKEN>

# Entropy analysis
python analysis/jwt_entropy_analysis.py --wordlist secrets/wordlist.txt
