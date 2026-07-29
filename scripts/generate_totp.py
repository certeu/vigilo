#!/usr/bin/env python3
"""generate-totp CLI

Generates 6-digit TOTP codes for MFA authentication testing.
Based on RFC 6238 (TOTP) and RFC 4226 (HOTP).

Usage:
    generate-totp --secret JBSWY3DPEHPK3PXP
"""

from __future__ import annotations

import hmac
import json
import math
import re
import struct
import sys
import time

BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def base32_decode(encoded: str) -> bytes:
    clean = re.sub(r"[^A-Z2-7]", "", encoded.upper())
    if not clean:
        raise ValueError("TOTP secret is empty after cleaning")

    output = []
    bits = 0
    value = 0
    for char in clean:
        idx = BASE32_ALPHABET.index(char)
        value = (value << 5) | idx
        bits += 5
        if bits >= 8:
            output.append((value >> (bits - 8)) & 0xFF)
            bits -= 8

    return bytes(output)


def generate_hotp(secret: str, counter: int, digits: int = 6) -> str:
    key = base32_decode(secret)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(key, counter_bytes, "sha1").digest()

    offset = digest[-1] & 0x0F
    code = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    return str(code % (10**digits)).zfill(digits)


def generate_totp(secret: str, time_step: int = 30, digits: int = 6) -> str:
    counter = math.floor(time.time() / time_step)
    return generate_hotp(secret, counter, digits)


def parse_secret(argv: list[str]) -> str:
    for i, arg in enumerate(argv):
        if arg == "--secret" and i + 1 < len(argv):
            return argv[i + 1]
    return ""


def main() -> None:
    secret = parse_secret(sys.argv)

    if not secret:
        print(json.dumps({"status": "error", "message": "Missing required --secret argument", "retryable": False}))
        sys.exit(1)

    if not re.match(r"^[A-Z2-7]+$", secret, re.IGNORECASE):
        print(json.dumps({"status": "error", "message": "Secret must be base32-encoded (A-Z and 2-7)", "retryable": False}))
        sys.exit(1)

    try:
        totp_code = generate_totp(secret)
        expires_in = 30 - (math.floor(time.time()) % 30)
        print(json.dumps({"status": "success", "totpCode": totp_code, "expiresIn": expires_in}))
    except Exception as e:
        print(json.dumps({"status": "error", "message": f"TOTP generation failed: {e}", "retryable": False}))
        sys.exit(1)


if __name__ == "__main__":
    main()
