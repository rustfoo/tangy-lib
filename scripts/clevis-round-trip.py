"""Exercise both general and explicitly selected advertisements with real Clevis."""

import json
import os
import subprocess
import sys

url, thumbprint = sys.argv[1:]
plaintext = b"Tangy interoperability regression\x00\xff\n"
env = {**os.environ, "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}

for config, flags in [({"url": url}, ["-y"]), ({"url": url, "thp": thumbprint}, [])]:
    encrypted = subprocess.run(
        ["clevis", "encrypt", "tang", json.dumps(config), *flags],
        input=plaintext, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, timeout=30,
    )
    if encrypted.returncode:
        raise RuntimeError(f"Encrypt with {config}: {encrypted.stderr.decode(errors='replace')}")
    decrypted = subprocess.run(
        ["clevis", "decrypt"], input=encrypted.stdout,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=30,
    )
    if decrypted.returncode:
        raise RuntimeError(decrypted.stderr.decode(errors="replace"))
    assert decrypted.stdout == plaintext, "Recovered plaintext differs"

print("Clevis round trips passed with default and explicitly selected signing keys")
