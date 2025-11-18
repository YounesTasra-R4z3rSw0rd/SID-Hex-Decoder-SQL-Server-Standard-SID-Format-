#!/usr/bin/env python3
import struct
import binascii
import sys

def sid_to_str(sid_bytes: bytes) -> str:
    """Convert binary SID to S-1-... string."""
    if not sid_bytes:
        return None

    revision, sub_authority_count = struct.unpack('BB', sid_bytes[:2])
    identifier_authority = int.from_bytes(sid_bytes[2:8], byteorder='big')

    sub_authorities = []
    for i in range(sub_authority_count):
        start = 8 + i * 4
        end = start + 4
        sub_authorities.append(struct.unpack('<I', sid_bytes[start:end])[0])

    sid_str = f"S-{revision}-{identifier_authority}"
    for sub_auth in sub_authorities:
        sid_str += f"-{sub_auth}"

    return sid_str


def main():
    # Check for argument or prompt the user
    if len(sys.argv) > 1:
        hex_sid = sys.argv[1]
    else:
        hex_sid = input("Enter SID in hex (e.g. 0x0105000000000005150000009B8AC404...): ").strip()

    # Sanitize and decode
    if hex_sid.startswith("0x") or hex_sid.startswith("0X"):
        hex_sid = hex_sid[2:]
    try:
        sid_bytes = binascii.unhexlify(hex_sid)
        sid_str = sid_to_str(sid_bytes)
        print(f"Decoded SID: {sid_str}")
    except Exception as e:
        print(f"[!] Error decoding SID: {e}")


if __name__ == "__main__":
    main()
