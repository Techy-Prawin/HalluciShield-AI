import json
from collections import Counter

sample_ids = []
with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\real500\raw_results.jsonl') as f:
    for i, line in enumerate(f):
        r = json.loads(line)
        sid = r.get('sample_id')
        sample_ids.append(sid)
        if i < 3:
            print(f'Sample {i}: sid={sid}, predicted={r.get("predicted_label")}, dc={r.get("detection_correct")}')

c = Counter(sample_ids)
dups = {k: v for k, v in c.items() if v > 1}
print(f'Duplicates: {len(dups)} sample_ids appear more than once')
if dups:
    for k, v in list(dups.items())[:5]:
        print(f'  {k}: {v} occurrences')