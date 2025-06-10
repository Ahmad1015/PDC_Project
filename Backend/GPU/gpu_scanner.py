import numpy as np
from numba import cuda
import math
import time
import json

MAX_SIGNATURES = 50000000
MAX_PATTERN_LENGTH = 10000

@cuda.jit
def scan_kernel_optimized(file_data, file_len, patterns, pattern_lengths, results):
    """Optimized kernel with better memory access patterns"""
    idx = cuda.grid(1)
    stride = cuda.gridsize(1)
    
    while idx < file_len:
        for s in range(patterns.shape[0]):
            pat_len = pattern_lengths[s]
            if idx + pat_len > file_len:
                continue

            match = True
            for j in range(pat_len):
                pattern_byte = patterns[s, j]
                if pattern_byte != 256:  # Not a wildcard
                    if file_data[idx + j] != pattern_byte:
                        match = False
                        break

            if match:
                cuda.atomic.add(results, s, 1)
        
        idx += stride

def gpu_malware_scan(file_path, signatures_data, max_signatures=None):
    """
    Complete GPU malware scanner - one function does it all!
    
    Args:
        file_path: Path to file to scan
        signatures_data: List of signature dictionaries OR path to JSON file
        max_signatures: Limit number of signatures (optional)
    """
    
    print("🚀 GPU MALWARE SCANNER")
    print("=" * 50)
    
    # ===== TOTAL TIMING START =====
    total_start = time.time()
    
    # ===== 1. LOAD SIGNATURES =====
    print("📖 Loading signatures...")
    load_start = time.time()
    
    # Handle both list input and file path input
    if isinstance(signatures_data, list):
        all_signatures = signatures_data
        print(f"   ✅ Using provided signature list")
    else:
        # Assume it's a file path
        with open(signatures_data, "r") as f:
            all_signatures = json.load(f)
        print(f"   ✅ Loaded from file: {signatures_data}")
    
    if max_signatures:
        all_signatures = all_signatures[:max_signatures]
    
    load_time = time.time() - load_start
    print(f"   ✅ Total signatures: {len(all_signatures):,} ({load_time:.3f}s)")
    
    # ===== 2. READ FILE =====
    print("📄 Reading target file...")
    read_start = time.time()
    
    with open(file_path, "rb") as f:
        file_bytes = f.read()
    file_len = len(file_bytes)
    
    read_time = time.time() - read_start
    print(f"   ✅ File: {file_path}")
    print(f"   ✅ Size: {file_len:,} bytes ({read_time:.3f}s)")
    
    # ===== 3. PROCESS SIGNATURES =====
    print("🔧 Processing signatures for GPU...")
    prep_start = time.time()
    
    valid_patterns = []
    pattern_lengths = []
    sig_names = []
    skipped = 0
    
    for sig in all_signatures:
        hex_str = sig["pattern"].strip().lower()
        
        # Validate hex pattern
        if len(hex_str) % 2 != 0 or len(hex_str) > MAX_PATTERN_LENGTH * 2:
            skipped += 1
            continue
            
        try:
            # Parse hex pattern
            pattern = []
            for i in range(0, len(hex_str), 2):
                pair = hex_str[i:i+2]
                if pair == '??':
                    pattern.append(256)  # Wildcard
                else:
                    pattern.append(int(pair, 16))
            
            valid_patterns.append(pattern)
            pattern_lengths.append(len(pattern))
            sig_names.append(sig["name"])
            
        except ValueError:
            skipped += 1
            continue
    
    prep_time = time.time() - prep_start
    print(f"   ✅ Valid signatures: {len(valid_patterns):,}")
    if skipped > 0:
        print(f"   ⚠️ Skipped invalid: {skipped:,}")
    print(f"   ✅ Processing time: {prep_time:.3f}s")
    
    if not valid_patterns:
        print("❌ No valid signatures found!")
        return
    
    # ===== 4. CREATE GPU ARRAYS =====
    print("🔧 Creating GPU arrays...")
    array_start = time.time()
    
    # Create pattern array (optimized with uint16)
    pattern_array = np.full((len(valid_patterns), MAX_PATTERN_LENGTH), 256, dtype=np.uint16)
    pattern_lengths_array = np.array(pattern_lengths, dtype=np.uint16)
    
    for i, pattern in enumerate(valid_patterns):
        plen = len(pattern)
        pattern_array[i, :plen] = np.array(pattern, dtype=np.uint16)
    
    array_time = time.time() - array_start
    print(f"   ✅ Arrays created ({array_time:.3f}s)")
    
    # ===== 5. GPU CONFIGURATION =====
    print("🎯 Configuring GPU...")
    config_start = time.time()
    
    device = cuda.get_current_device()
    multiprocessor_count = device.MULTIPROCESSOR_COUNT
    
    # Optimize configuration based on file size
    if file_len < 1024 * 1024:  # Small files
        threads_per_block = 128
        blocks_per_grid = min(multiprocessor_count * 8, (file_len + threads_per_block - 1) // threads_per_block)
    else:  # Large files
        threads_per_block = 256
        blocks_per_grid = min(multiprocessor_count * 16, (file_len + threads_per_block - 1) // threads_per_block)
    
    blocks_per_grid = max(blocks_per_grid, multiprocessor_count * 2)
    total_threads = blocks_per_grid * threads_per_block
    
    config_time = time.time() - config_start
    print(f"   ✅ Blocks: {blocks_per_grid:,}")
    print(f"   ✅ Threads per block: {threads_per_block}")
    print(f"   ✅ Total threads: {total_threads:,}")
    print(f"   ✅ Config time: {config_time:.3f}s")
    
    # ===== 6. GPU MEMORY TRANSFER =====
    print("📤 Transferring to GPU...")
    transfer_start = time.time()
    
    # Transfer data to GPU
    file_data_gpu = cuda.to_device(np.frombuffer(file_bytes, dtype=np.uint8))
    patterns_gpu = cuda.to_device(pattern_array)
    lengths_gpu = cuda.to_device(pattern_lengths_array)
    results_gpu = cuda.device_array(len(valid_patterns), dtype=np.int32)
    
    transfer_time = time.time() - transfer_start
    print(f"   ✅ GPU transfer complete ({transfer_time:.3f}s)")
    
    # ===== 7. GPU KERNEL EXECUTION =====
    print("🚀 Launching GPU scan kernel...")
    kernel_start = time.time()
    
    scan_kernel_optimized[blocks_per_grid, threads_per_block](
        file_data_gpu, file_len, patterns_gpu, lengths_gpu, results_gpu
    )
    cuda.synchronize()
    
    kernel_time = time.time() - kernel_start
    print(f"   ✅ GPU kernel complete ({kernel_time:.3f}s)")
    
    # ===== 8. RETRIEVE RESULTS =====
    print("📥 Getting results...")
    retrieve_start = time.time()
    
    results = results_gpu.copy_to_host()
    
    retrieve_time = time.time() - retrieve_start
    print(f"   ✅ Results retrieved ({retrieve_time:.3f}s)")
    
    # ===== 9. PROCESS AND DISPLAY RESULTS =====
    print("\n🔍 SCAN RESULTS:")
    print("=" * 50)
    
    matches_found = 0
    total_occurrences = 0
    matched_signatures = []
    
    for i, count in enumerate(results):
        if count > 0:
            matches_found += 1
            total_occurrences += count
            matched_signatures.append((sig_names[i], count))
    
    # Display match results prominently
    if matches_found == 0:
        print("✅ CLEAN - No malware signatures detected!")
        print("   File appears to be safe.")
    else:
        print("🚨 MALWARE DETECTED!")
        print(f"   Found {matches_found} different signature(s)")
        print(f"   Total occurrences: {total_occurrences}")
        print("\n📋 Detected signatures:")
        for sig_name, count in matched_signatures:
            print(f"   🔴 {sig_name} - {count} occurrence{'s' if count > 1 else ''}")
    
    # ===== 10. PERFORMANCE SUMMARY =====
    total_time = time.time() - total_start
    
    print(f"\n⏱️ PERFORMANCE BREAKDOWN:")
    print("=" * 50)
    print(f"   Signature loading: {load_time:.3f}s")
    print(f"   File reading: {read_time:.3f}s") 
    print(f"   Signature processing: {prep_time:.3f}s")
    print(f"   Array creation: {array_time:.3f}s")
    print(f"   GPU configuration: {config_time:.3f}s")
    print(f"   GPU memory transfer: {transfer_time:.3f}s")
    print(f"   🚀 GPU kernel execution: {kernel_time:.3f}s ⭐")
    print(f"   Result retrieval: {retrieve_time:.3f}s")
    print(f"   ⏱️ TOTAL SCAN TIME: {total_time:.3f}s")
    
    # Performance metrics
    bytes_per_second = file_len / total_time if total_time > 0 else 0
    signatures_per_second = len(valid_patterns) / total_time if total_time > 0 else 0
    scan_rate = (file_len * len(valid_patterns)) / total_time if total_time > 0 else 0
    efficiency = (kernel_time / total_time) * 100 if total_time > 0 else 0
    
    print(f"\n📊 PERFORMANCE METRICS:")
    print("=" * 50)
    print(f"   File throughput: {bytes_per_second:,.0f} bytes/sec")
    print(f"   Signature rate: {signatures_per_second:,.0f} sigs/sec")
    print(f"   Scan rate: {scan_rate:,.0f} comparisons/sec")
    print(f"   GPU efficiency: {efficiency:.1f}% compute time")
    
    print(f"\n📈 SCAN SUMMARY:")
    print("=" * 50)
    print(f"   File scanned: {file_path}")
    print(f"   File size: {file_len:,} bytes")
    print(f"   Signatures checked: {len(valid_patterns):,}")
    print(f"   Scan time: {total_time:.3f}s")
    print(f"   Status: {'🚨 INFECTED' if matches_found > 0 else '✅ CLEAN'}")
    
    if matches_found > 0:
        print(f"   Threats found: {matches_found}")
        print(f"   Total detections: {total_occurrences}")
    
    # Return results for programmatic use
    return {
        'file_path': file_path,
        'file_size': file_len,
        'signatures_checked': len(valid_patterns),
        'matches_found': matches_found,
        'total_occurrences': total_occurrences,
        'matched_signatures': matched_signatures,
        'scan_time': total_time,
        'kernel_time': kernel_time,
        'is_infected': matches_found > 0
    }

# Simple usage examples
if __name__ == "__main__":
    # Example 1: Using a signature list (your use case)
    signatures_list = [
        {"name": "EICAR-Test-File", "pattern": "58354f21503f24...."},
        # ... more signatures
    ]
    result = gpu_malware_scan("test_file.exe", signatures_list)
    
    # Example 2: Using a JSON file
    # result = gpu_malware_scan("test_file.exe", "signatures.json")
    
    # Result is also returned as a dictionary for further processing
    if result and result['is_infected']:
        print(f"\n⚠️ WARNING: {result['matches_found']} threats detected!")
    else:
        print(f"\n✅ File is clean!")