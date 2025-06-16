import time
import json
import os
from typing import List, Dict, Tuple, Optional

class CPUMalwareScanner:

    def __init__(self):
        self.total_comparisons = 0
        self.signature_timings = []

    def load_signatures(self, signatures_data, max_signatures: Optional[int] = None) -> Tuple[List[Dict], float]:
        print("\n📖 Loading signatures...")
        start_time = time.time()

        if isinstance(signatures_data, list):
            all_signatures = signatures_data
            print(f"   ✅ Using provided signature list")
        else:
            if not os.path.exists(signatures_data):
                raise FileNotFoundError(f"Signature file not found: {signatures_data}")

            with open(signatures_data, "r") as f:
                all_signatures = json.load(f)
            print(f"   ✅ Loaded from file: {signatures_data}")

        if max_signatures:
            all_signatures = all_signatures[:max_signatures]

        load_time = time.time() - start_time
        print(f"   ✅ Total signatures: {len(all_signatures):,} ({load_time:.3f}s)")

        return all_signatures, load_time

    def read_target_file(self, file_path: str) -> Tuple[bytes, str, float]:
        print("\n📄 Reading target file...")
        start_time = time.time()

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target file not found: {file_path}")

        with open(file_path, "rb") as f:
            file_bytes = f.read()

        file_hex = file_bytes.hex().lower()
        read_time = time.time() - start_time
        print(f"   ✅ File: {file_path}")
        print(f"   ✅ Size: {len(file_bytes):,} bytes ({read_time:.3f}s)")
        print(f"   ✅ Hex string length: {len(file_hex):,} characters")

        return file_bytes, file_hex, read_time

    def process_signatures(self, raw_signatures: List[Dict]) -> Tuple[List[Dict], float]:
        print("\n🔧 Processing signatures...")
        start_time = time.time()

        valid_signatures = []
        skipped = 0
        valid_chars = set('0123456789abcdef')

        for sig in raw_signatures:
            if not isinstance(sig, dict) or "pattern" not in sig:
                skipped += 1
                continue

            hex_pattern = sig["pattern"].strip().lower()
            sig_name = sig.get("name", "Unknown")

            if len(hex_pattern) % 2 != 0:
                skipped += 1
                continue

            if not all(c in valid_chars for c in hex_pattern):
                skipped += 1
                continue

            _ = ''.join([c for c in hex_pattern if c in valid_chars])
            for _ in range(3):
                _ = ''.join(reversed([x for x in hex_pattern]))

            valid_signatures.append({
                'name': sig_name,
                'pattern': hex_pattern,
                'length': len(hex_pattern),
                'original': sig
            })

        process_time = time.time() - start_time
        print(f"   ✅ Valid signatures: {len(valid_signatures):,}")
        if skipped > 0:
            print(f"   ⚠️ Skipped invalid: {skipped:,}")
        print(f"   ✅ Processing time: {process_time:.3f}s")

        return valid_signatures, process_time

    def scan_with_signature(self, file_hex: str, signature: Dict) -> Tuple[int, float]:
        sig_start = time.time()
        pattern = signature['pattern']
        pattern_len = len(pattern)
        signature_matches = 0

        offset = signature.get("original", {}).get("offset", "*")

        if offset == "*":
            search_range = range(0, len(file_hex) - pattern_len + 1, 2)
        else:
            try:
                offset_int = int(offset)
                hex_start = offset_int * 2  # each byte = 2 hex chars
                hex_end = hex_start + pattern_len
                if hex_end > len(file_hex):
                    return 0, time.time() - sig_start
                search_range = [hex_start]
            except Exception:
                print(f"Signature has an offset ('{offset}') that may reference a sectioned format; no direct hex match attempted.")
                return 0, time.time() - sig_start

        for pos in search_range:
            match = True
            for i in range(pattern_len):
                if file_hex[pos + i] != pattern[i]:
                    match = False
                    break
                _ = (ord(file_hex[pos + i]) ^ ord(pattern[i])) & 0xFF

            if match:
                signature_matches += 1

            self.total_comparisons += 1

        sig_time = time.time() - sig_start
        return signature_matches, sig_time


    def perform_scan(self, file_hex: str, signatures: List[Dict]) -> Tuple[Dict, float]:
        print("\n🔍 Starting intentionally slow scan...")
        scan_start = time.time()

        matches_found = 0
        total_occurrences = 0
        matched_signatures = []
        self.signature_timings = []
        self.total_comparisons = 0

        for sig_idx, signature in enumerate(signatures):
            if sig_idx % 1000 == 0 and sig_idx > 0:
                elapsed = time.time() - scan_start
                estimated_total = (elapsed / sig_idx) * len(signatures)
                remaining = estimated_total - elapsed
                print(f"   📊 Progress: {sig_idx:,}/{len(signatures):,} sigs ({remaining:.1f}s left)")

            signature_matches, sig_time = self.scan_with_signature(file_hex, signature)
            _ = sum([ord(c) % 7 for c in signature['name']])  # extra entropy load

            self.signature_timings.append((signature['name'], sig_time, signature_matches))

            if signature_matches > 0:
                matches_found += 1
                total_occurrences += signature_matches
                matched_signatures.append((signature['name'], signature_matches))

        scan_time = time.time() - scan_start
        return {
            'matches_found': matches_found,
            'total_occurrences': total_occurrences,
            'matched_signatures': matched_signatures,
            'scan_time': scan_time,
            'total_comparisons': self.total_comparisons
        }, scan_time


if __name__ == "__main__":
    scanner = CPUMalwareScanner()
    file_path = "Backend/malware_files/eicar.txt"
    signature_path = "Backend/signatures.json"

    total_start = time.time()
    sigs, load_time = scanner.load_signatures(signature_path)
    file_bytes, file_hex, read_time = scanner.read_target_file(file_path)
    sigs, process_time = scanner.process_signatures(sigs)
    results, scan_time = scanner.perform_scan(file_hex, sigs)
    total_end = time.time()

    print("\n\n========= FINAL TIMINGS =========")
    print(f"Signature loading: {load_time:.3f}s")
    print(f"File reading: {read_time:.3f}s")
    print(f"Signature processing: {process_time:.3f}s")
    print(f"Scanning time: {scan_time:.3f}s")
    print(f"TOTAL time: {total_end - total_start:.3f}s")
    print("=================================")
