from file_utils import list_files_in_directory, read_file_in_chunks

files = list_files_in_directory("malware_files/")
for path in files:
    print(f"Scanning: {path}")
    for chunk in read_file_in_chunks(path):
        print(f"Read {len(chunk)} bytes")
