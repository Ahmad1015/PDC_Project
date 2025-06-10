import os

def list_files_in_directory(directory, extensions=None):
    """
    Recursively list all files in the given directory.
    If extensions is provided, filter by file extensions (e.g., ['.exe', '.dll']).
    """
    files = []
    for root, _, filenames in os.walk(directory):
        for fname in filenames:
            if extensions is None or any(fname.lower().endswith(ext.lower()) for ext in extensions):
                files.append(os.path.join(root, fname))
    return files

def read_file_in_chunks(filepath, chunk_size=1024*1024):
    """
    Generator that yields chunks of the file.
    """
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk
