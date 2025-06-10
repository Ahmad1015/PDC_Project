import json
import time

def read_file_bytes(filepath):
    """Read full file as bytes"""
    with open(filepath, "rb") as f:
        return f.read()

def stream_signatures(filepath):
    """Generator that yields one JSON object at a time from a large JSON array file."""
    with open(filepath, 'r') as f:
        # Skip the initial whitespace and the opening '['
        while (c := f.read(1)) and c not in ['[']:
            continue

        buffer = ''
        depth = 0
        in_string = False
        inside_object = False

        while True:
            c = f.read(1)
            if not c:
                break

            if c == '{' and not in_string:
                depth += 1
                inside_object = True

            if inside_object:
                buffer += c

            if c == '"' and buffer and buffer[-2] != '\\':  # Handle escaped quotes
                in_string = not in_string

            if c == '}' and not in_string:
                depth -= 1
                if depth == 0:
                    yield json.loads(buffer)
                    buffer = ''
                    inside_object = False


def scan_file(file_path, signature_path):
    start_time = time.time()
    comparison_count = 0
    file_bytes = read_file_bytes(file_path)

    matches = []
    for sig in stream_signatures(signature_path):
        pattern_hex = sig.get("pattern", "").lower()
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

    if not matches:
        print("[-] No matches found.")
    return matches

if __name__ == "__main__":
    scan_file("malware_files/eicar.txt", "C:/Users/mahme/Downloads/extract/signatures.json")
