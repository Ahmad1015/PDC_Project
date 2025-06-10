import json

def parse_ndb_line(line):
    parts = line.strip().split(':')
    if len(parts) < 4:
        return None  # malformed line

    name = parts[0]
    pattern_type = parts[1]
    offset = parts[2]
    hex_pattern = parts[3]

    # Optionally validate hex pattern (allow hex + wildcards)
    return {
        "name": name,
        "type": pattern_type,
        "offset": offset,
        "pattern": hex_pattern.lower()
    }

def parse_ndb_file(file_path):
    signatures = []
    with open(file_path, 'r') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue  # skip comments/empty lines
            parsed = parse_ndb_line(line)
            if parsed:
                signatures.append(parsed)
    return signatures

def save_to_json(data, output_path):
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)

if __name__ == "__main__":
    input_file = "main.ndb"
    output_file = "signatures.json"

    print(f"Parsing {input_file}...")
    signatures = parse_ndb_file(input_file)
    print(f"Parsed {len(signatures)} signatures.")
    
    print(f"Saving to {output_file}...")
    save_to_json(signatures, output_file)
    print("Done ✅")
