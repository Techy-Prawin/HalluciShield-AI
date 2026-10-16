import json
from collections import Counter

with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\pilot20\trace_summary.json') as f:
    data = json.load(f)

# Check stages_completed for each sample
stage_counts = Counter()
for item in data:
    stages = tuple(item.get('stages_completed', []))
    stage_counts[stages] += 1
    print(f"{item['sample_id']}: stages={stages}, validation_status={item.get('validation_status')}")

print(f'\nStage distribution: {dict(stage_counts)}')
print(f'Total: {len(data)}')

# Check how many completed all 7 stages
all_seven = sum(1 for item in data if len(item.get('stages_completed', [])) == 7)
not_all_seven = len(data) - all_seven
print(f'\nCompleted all 7 stages: {all_seven}/{len(data)}')
print(f'Did not complete all 7: {not_all_seven}/{len(data)}')

# Check validation_status distribution
val_counts = Counter()
for item in data:
    val = item.get('validation_status', 'UNKNOWN')
    val_counts[val] += 1
print(f'\nValidation status distribution: {dict(val_counts)}')

# Check scanner_status distribution
scanner_counts = Counter()
for item in data:
    s = item.get('scanner_status', 'UNKNOWN')
    scanner_counts[s] += 1
print(f'Scanner status distribution: {dict(scanner_counts)}')