import json
with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\evaluation\results\research\ablation500\metrics.json') as f:
    m = json.load(f)
c = m['configurations_detail']
for k, v in c.items():
    det = v['detection']
    print(f'{k}: P={det["precision"]}, R={det["recall"]}, F1={det["f1"]}, Acc={det["accuracy"]}, FPR={det["fpr"]}, FNR={det["fnr"]}')