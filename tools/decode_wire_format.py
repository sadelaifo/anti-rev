#!/usr/bin/env python3
"""Decode protobuf wire format from hex string.

Usage:
    python3 decode_wire_format.py <hex_string>
    echo "<hex_string>" | python3 decode_wire_format.py
"""
import sys

def read_varint(data, pos):
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        result |= (b & 0x7f) << shift
        pos += 1
        if (b & 0x80) == 0:
            return result, pos
        shift += 7
    return result, pos

def decode_msg(data, depth=0):
    pos = 0
    prefix = "  " * depth
    while pos < len(data):
        if pos >= len(data):
            break
        tag, pos = read_varint(data, pos)
        fn = tag >> 3
        wt = tag & 0x7

        if wt == 0:  # varint
            val, pos = read_varint(data, pos)
            print(f"{prefix}field={fn} varint={val}")
        elif wt == 2:  # length-delimited
            length, pos = read_varint(data, pos)
            if pos + length > len(data):
                print(f"{prefix}field={fn} LEN={length} (TRUNCATED, only {len(data)-pos} bytes left)")
                payload = data[pos:]
                print(f"{prefix}  hex: {payload.hex()}")
                try:
                    print(f"{prefix}  str: \"{payload.decode('utf-8', errors='replace')}\"")
                except:
                    pass
                break
            payload = data[pos:pos + length]
            pos += length
            # try as printable string
            try:
                s = payload.decode("utf-8")
                if all(32 <= c < 127 for c in payload):
                    print(f"{prefix}field={fn} string=\"{s}\"")
                    continue
            except:
                pass
            # try as sub-message
            print(f"{prefix}field={fn} submessage (len={length}):")
            try:
                decode_msg(payload, depth + 1)
            except:
                print(f"{prefix}  (decode failed, raw hex: {payload.hex()})")
        elif wt == 1:  # 64-bit
            if pos + 8 > len(data):
                print(f"{prefix}field={fn} fixed64 (TRUNCATED)")
                break
            val = int.from_bytes(data[pos:pos+8], "little")
            pos += 8
            print(f"{prefix}field={fn} fixed64={val}")
        elif wt == 5:  # 32-bit
            if pos + 4 > len(data):
                print(f"{prefix}field={fn} fixed32 (TRUNCATED)")
                break
            val = int.from_bytes(data[pos:pos+4], "little")
            pos += 4
            print(f"{prefix}field={fn} fixed32={val}")
        else:
            print(f"{prefix}field={fn} UNKNOWN wire_type={wt} -- STOP")
            break

if __name__ == "__main__":
    if len(sys.argv) > 1:
        hex_str = sys.argv[1].strip().replace(" ", "")
    else:
        hex_str = sys.stdin.read().strip().replace(" ", "")

    data = bytes.fromhex(hex_str)
    print(f"Total bytes: {len(data)}")
    print()
    decode_msg(data)
