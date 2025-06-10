# gpu_scan_caller.py

from signature_loader import load_signatures
from gpu_scanner import scan_file_with_gpu

signatures = load_signatures("C:/Users/mahme/Downloads/extract/Backend/signatures.json")
scan_file_with_gpu("C:/Users/mahme/Downloads/extract/Backend/malware_files/eicar.txt", signatures)
