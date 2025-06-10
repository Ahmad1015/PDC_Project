import json

def hex_to_bytes_and_mask(hex_str, sig_name=None):
    if len(hex_str) % 2 != 0:
        raise ValueError(f"Invalid hex pattern length in signature {sig_name}")

    byte_array = bytearray()
    mask_array = bytearray()

    i = 0
    while i < len(hex_str):
        pair = hex_str[i:i+2]
        if pair == "??":
            byte_array.append(0x00)
            mask_array.append(0x00)
        else:
            byte_array.append(int(pair, 16))
            mask_array.append(0xFF)
        i += 2

    return bytes(byte_array), bytes(mask_array)


def load_signatures(filename):
    import json

    with open(filename, "r") as f:
        raw_sigs = json.load(f)

    processed = []
    for sig in raw_sigs:
        try:
            byte_seq, mask = hex_to_bytes_and_mask(sig["pattern"], sig.get("name"))
            sig["bytes"] = byte_seq
            sig["mask"] = mask
            
            # Add this debug block:
            if sig["name"] == "EICAR-Test-File":
                with open("debug_signature_load.log", "a") as logf:
                    logf.write(f"Loaded {sig['name']} pattern length: {len(byte_seq)} bytes\n")
                    logf.write(f"Pattern bytes (hex): {byte_seq.hex()}\n\n")

            processed.append(sig)
        except Exception as e:
            print(f"⚠️ Error in signature {sig.get('name', '?')}: {e}")
            continue

    print(f"✅ Loaded {len(processed)} valid signatures.")
    for i, sig in enumerate(processed[:5]):
        print(f"{i+1}. {sig['name']} ({len(sig['bytes'])} bytes)")
    return processed


