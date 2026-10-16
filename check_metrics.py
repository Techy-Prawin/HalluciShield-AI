import json
with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\metrics.json') as f:
    m = json.load(f)
configs = m.get('configurations', {})
for k, v in configs.items():
    if 'metrics' in v:
        met = v['metrics']
        print(f'{k}: P={met.get("precision")}, R={met.get("recall")}, F1={met.get("f1")}, Acc={met.get("accuracy")}')
    else:
        print(f'{k}: no metrics')