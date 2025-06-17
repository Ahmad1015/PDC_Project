import json
import time
import io

def read_file_bytes(filepath):
    with open(filepath, "rb") as f:
        return f.read()

def stream_signatures(filepath):
    with open(filepath, 'r') as f:
        # Skip until we reach the opening '[' of the JSON array
        for c in iter(lambda: f.read(1), ''):
            if c == '[':
                break

        buffer = []
        depth = 0
        in_string = False
        escape = False

        while True:
            c = f.read(1)
            if not c:
                break

            if escape:
                escape = False
            elif c == '\\':
                escape = True
            elif c == '"':
                in_string = not in_string
            elif not in_string:
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1

            if depth > 0 or (depth == 0 and c == '}'):
                buffer.append(c)

            if depth == 0 and buffer:
                obj_str = ''.join(buffer)
                try:
                    yield json.loads(obj_str)
                except json.JSONDecodeError:
                    pass  # Could log here
                buffer.clear()

def scan_file(file_path, signature_path):
    start_time = time.time()
    comparison_count = 0

    file_bytes = read_file_bytes(file_path)
    file_len = len(file_bytes)

    matches = []
    for sig in stream_signatures(signature_path):
        pattern_hex = sig.get("pattern", "")
        if not pattern_hex:
            continue
        try:
            pattern_bytes = bytes.fromhex(pattern_hex)
        except ValueError:
            continue

        comparison_count += 1
        if pattern_bytes in file_bytes:
            print(f"[+] Match found: {sig['name']}")
            matches.append(sig['name'])

    elapsed = time.time() - start_time
    print("\n[-] Scan finished.")
    print(f"[i] Total signatures scanned: {comparison_count}")
    print(f"[i] Time taken: {elapsed:.2f} seconds")
    print(f"[i] File byte length: {file_len}")
    if not matches:
        print("[-] No matches found.")
    return matches

if __name__ == "__main__":
    print("[*] Starting scan...")
    matches = scan_file(
        r"C:\Users\mahme\pdc\PDC_Project\Backend\CPU\big.txt",
        r"C:\Users\mahme\pdc\PDC_Project\Backend\signatures.json"
    )
    print(matches)
