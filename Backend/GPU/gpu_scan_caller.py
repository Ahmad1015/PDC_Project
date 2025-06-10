# gpu_scan_caller.py

from signature_loader import load_signatures
from gpu_scanner import gpu_malware_scan

signatures = load_signatures("C:/Users/mahme/Downloads/extract/Backend/signatures.json")
result =gpu_malware_scan("C:/Users/mahme/Downloads/extract/Backend/malware_files/eicar.txt", signatures)
