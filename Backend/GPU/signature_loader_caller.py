from signature_loader import load_signatures

signatures = load_signatures("signatures.json")

print(f"\n✅ Loaded {len(signatures)} valid signatures.\n")

# Optional: Show a few for verification
for i, sig in enumerate(signatures[:5]):
    print(f"{i+1}. {sig['name']} ({len(sig['pattern_bytes'])} bytes)")
