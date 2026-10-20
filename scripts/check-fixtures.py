"""Independently check committed vectors with Latchset JOSE (no Rust code)."""

import json
from pathlib import Path
import subprocess

fixtures = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def jose(*args, input=None):
    return subprocess.check_output(["jose", *args], input=input, text=True, timeout=10).strip()


for name, expected in json.loads((fixtures / "thumbprints.json").read_text()).items():
    assert jose("jwk", "thp", "-i", str(fixtures / name), "-a", "S256") == expected

for vector in json.loads((fixtures / "recovery.json").read_text()):
    response = json.loads(jose(
        "jwk", "exc", "-i", '{"alg":"ECMR"}',
        "-l", str(fixtures / "ecmr.json"), "-r", "-", input=json.dumps(vector["request"]),
    ))
    assert "d" not in response
    # tangd adds these two metadata fields after jose_jwk_exc().
    response.update(alg="ECMR", key_ops=["deriveKey"])
    assert response == vector["response"], "Recovery vector differs from JOSE"

print("JOSE verified all thumbprints and recovery vectors")
