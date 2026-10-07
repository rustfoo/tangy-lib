"""Exercise stock Clevis recovery/enrollment and independently verify the old signer.

Clevis thp trust checks require a matching signing key inside the payload; Tang's
active-only rotated advertisement cannot meet that check for an old thumbprint.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

url, thumbprint, rotate_request, rotated_ready = sys.argv[1:]
plaintext = b"Tangy rotation interoperability\x00\xff\n"
env = {**os.environ, "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1", "LC_ALL": "C"}
http = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def run(args, data):
    return subprocess.run(args, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=env, timeout=30)


def successful(args, data):
    result = run(args, data)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result.stdout


def advertisement(kid):
    with http.open(f"{url}/adv/{kid}", timeout=10) as response:
        return json.load(response)


def keys(adv):
    return json.loads(base64.urlsafe_b64decode(adv["payload"] + "=="))["keys"]


def key_id(key):
    return successful(["jose", "jwk", "thp", "-i-"], json.dumps(key).encode()).decode().strip()


old_signer = next(key for key in keys(advertisement(thumbprint)) if key_id(key) == thumbprint)
config = json.dumps({"url": url, "thp": thumbprint})
original = successful(["clevis", "encrypt", "tang", config], plaintext)
Path(rotate_request).write_text("rotate")
deadline = time.monotonic() + 20
while not Path(rotated_ready).exists():
    if time.monotonic() > deadline:
        raise TimeoutError("Server did not rotate")
    time.sleep(0.01)
assert successful(["clevis", "decrypt"], original) == plaintext, "Pre-rotation binding no longer recovers"

selected = advertisement(thumbprint)
active = keys(selected)
assert all(key_id(key) != thumbprint for key in active), "Rotated key was advertised"
# JOSE verifies an actual old-key signature over the new active payload.
successful(["jose", "jws", "ver", "-i", json.dumps(selected), "-k-"], json.dumps(old_signer).encode())
# A retired thp cannot pass stock Clevis's payload-based trust check, even with
# that valid signature. Pin the limitation so we never claim false compatibility.
rejected = run(["clevis", "encrypt", "tang", config], plaintext)
assert rejected.returncode != 0, "Clevis unexpectedly accepted an absent old signer"
assert f"Trusted JWK '{thumbprint}' did not sign the advertisement!" in rejected.stderr.decode(), rejected.stderr.decode()

current = next(key_id(key) for key in active if key["alg"] == "ES512")
new_config = json.dumps({"url": url, "thp": current})
new = successful(["clevis", "encrypt", "tang", new_config], plaintext)
assert successful(["clevis", "decrypt"], new) == plaintext, "New binding with current signing trust failed"
print("Clevis recovered the old binding and enrolled with the current thumbprint; JOSE verified the old signature")
