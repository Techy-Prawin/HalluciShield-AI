With open('eval_full.txt', 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()
# Just print the first 2000 chars safely
for i in range(0, min(2000, len(content)), 2000):
    chunk = content[i:i+2000]
    # Replace problematic chars
    safe = chunk.replace('\u2192', '->').replace('\u00a0', ' ')
    print(f"CHUNK {i//2000 + 1}:")
    print(safe)
    print("---")