import numpy as np
from numba import cuda
import math

MAX_SIGNATURES = 50000000
MAX_PATTERN_LENGTH = 10000

@cuda.jit
def scan_kernel(file_data, file_len, patterns, pattern_lengths, results):
    idx = cuda.grid(1)
    if idx >= file_len:
        return

    for s in range(patterns.shape[0]):
        pat_len = pattern_lengths[s]
        if idx + pat_len > file_len:
            continue

        match = True
        for j in range(pat_len):
            pattern_byte = patterns[s, j]
            if pattern_byte == 256:  # Wildcard
                continue
            if file_data[idx + j] != pattern_byte:
                match = False
                break

        if match:
            cuda.atomic.add(results, s, 1)

def parse_hex_pattern(hex_str):
    pattern = []
    for i in range(0, len(hex_str), 2):
        pair = hex_str[i:i+2]
        if pair == '??':
            pattern.append(256)
        else:
            pattern.append(int(pair, 16))
    return pattern

def scan_file_with_gpu(file_path, loaded_signatures):
    with open(file_path, "rb") as f:
        file_bytes = f.read()
    file_len = len(file_bytes)

    print(f"📄 Loaded {file_path} ({file_len} bytes)")
    print(f"🚀 Preparing GPU memory...")

    sigs = loaded_signatures[:MAX_SIGNATURES]
    sig_patterns = []
    sig_names = []

    for sig in sigs:
        hex_str = sig["pattern"].strip().lower()
        if len(hex_str) % 2 != 0:
            print(f"❌ Odd-length hex in {sig['name']}")
            continue
        try:
            pattern = parse_hex_pattern(hex_str)
            if len(pattern) > MAX_PATTERN_LENGTH:
                print(f"⚠️ Skipping {sig['name']}: pattern too long ({len(pattern)} bytes)")
                continue
            
            sig_patterns.append(pattern)
            sig_names.append(sig["name"])
        except ValueError as e:
            print(f"⚠️ Skipping {sig['name']}: {e}")
            continue

    if not sig_patterns:
        print("❌ No valid signatures to scan!")
        return
        

    # Initialize pattern array with wildcards (256)
    pattern_array = np.full((len(sig_patterns), MAX_PATTERN_LENGTH), 256, dtype=np.int32)
    pattern_lengths = np.zeros(len(sig_patterns), dtype=np.int32)

    for i, pattern in enumerate(sig_patterns):
        plen = len(pattern)
        pattern_array[i, :plen] = np.array(pattern, dtype=np.int32)
        pattern_lengths[i] = plen

    # Debug: Check EICAR signature
    eicar_index = None
    for i, name in enumerate(sig_names):
        if "EICAR" in name.upper():
            eicar_index = i
            break
    if eicar_index is not None:
        print("\n🔍 EICAR Signature Debug:")
        print(f"Name: {sig_names[eicar_index]}")
        print(f"Hex Pattern: {sigs[eicar_index]['pattern']}")
        print(f"Parsed Bytes (hex): {[f'{x:02x}' for x in sig_patterns[eicar_index]]}")
        print(f"File Bytes (hex): {file_bytes[:len(sig_patterns[eicar_index])].hex()}")
        print(f"Pattern Length: {pattern_lengths[eicar_index]}")

    # Transfer data to GPU
    d_file_data = cuda.to_device(np.frombuffer(file_bytes, dtype=np.uint8))
    d_patterns = cuda.to_device(pattern_array)
    d_lengths = cuda.to_device(pattern_lengths)
    d_results = cuda.to_device(np.zeros(len(sig_patterns), dtype=np.int32))

    # Launch kernel
    threads_per_block = 256
    blocks_per_grid = (file_len + threads_per_block - 1) // threads_per_block

    scan_kernel[blocks_per_grid, threads_per_block](d_file_data, file_len, d_patterns, d_lengths, d_results)
    cuda.synchronize()

    results = d_results.copy_to_host()
    print("\n✅ Scan complete.\n")

    for i, matched in enumerate(results):
        if matched:
            print(f"⚠️ Match found: {sig_names[i]}")

    if not any(results):
        print("✅ No matches found.")