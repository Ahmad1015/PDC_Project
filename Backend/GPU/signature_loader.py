import json

def hex_to_bytes_and_mask(hex_str, sig_name=None):
    # Handle odd-length hex strings by padding with '0'
    if len(hex_str) % 2 != 0:
        hex_str = hex_str + '0'  # Pad with zero at the end

    byte_array = bytearray()
    mask_array = bytearray()

    i = 0
    while i < len(hex_str):
        pair = hex_str[i:i+2]
        if pair == "??":
            byte_array.append(0x00)
            mask_array.append(0x00)
        else:
            try:
                byte_array.append(int(pair, 16))
                mask_array.append(0xFF)
            except ValueError:
                raise ValueError(f"Invalid hex pair '{pair}' in signature {sig_name}")
        i += 2

    return bytes(byte_array), bytes(mask_array)


def load_signatures(filename):
    with open(filename, "r") as f:
        raw_sigs = json.load(f)

    processed = []
    
    for sig in raw_sigs:
        try:
            pattern = sig.get("pattern", "")
            byte_seq, mask = hex_to_bytes_and_mask(pattern, sig.get("name"))
            sig["bytes"] = byte_seq
            sig["mask"] = mask
            
            processed.append(sig)
            
        except Exception as e:
            continue

    print(f"✅ Loaded {len(processed)} valid signatures.")
    return processed