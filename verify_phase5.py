import json

# Check multi_patch config.json
with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\multi_patch\config.json', 'r') as f:
    mp_config = json.load(f)
print('=== Multi-Patch config.json ===')
print(f'evaluation_mode: {mp_config.get("evaluation_mode")}')
print(f'provenance: {mp_config.get("provenance")}')
note = mp_config.get("note", "")
print(f'note starts with: {note[:60]}...')

# Check multi_patch metrics.json
with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\multi_patch\metrics.json', 'r') as f:
    mp_metrics = json.load(f)
print()
print('=== Multi-Patch metrics.json ===')
print(f'provenance: {mp_metrics.get("provenance")}')
print(f'controlled_fixture: {mp_metrics.get("controlled_fixture")}')

# Check causal analysis config.json
with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\causal_analysis\config.json', 'r') as f:
    ca_config = json.load(f)
print()
print('=== Causal Analysis config.json ===')
print(f'evaluation_mode: {ca_config.get("evaluation_mode")}')
print(f'provenance: {ca_config.get("provenance")}')
note = ca_config.get("note", "")
print(f'note starts with: {note[:60]}...')

# Check causal analysis README
with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode
<parameter=command>
python << 'PYEOF'
import json

# Check multi_patch