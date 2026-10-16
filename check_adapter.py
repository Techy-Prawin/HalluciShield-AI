import sys
from pathlib import Path
repo = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
sys.path.insert(0, str(repo))
sys.path.insert(0, str(repo / 'ai-engine'))
from evaluation.dataset_b.full_ace_adapter import FullACEAdapter
adapter = FullACEAdapter()
# Check what attributes/methods the adapter has
print("Adapter attributes:")
for attr in dir(adapter):
    if not attr.startswith('__'):
        print(f"  {attr}")