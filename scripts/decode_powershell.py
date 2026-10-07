import base64
import sys

if len(sys.argv) != 2:
    print("Usage: python3 scripts/decode_powershell.py <base64>")
    sys.exit(1)

encoded = sys.argv[1]

try:
    decoded = base64.b64decode(encoded).decode("utf-16le")
    print(decoded)
except Exception as e:
    print("Decode failed:", e)