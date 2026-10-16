import sys
from pathlib import Path
_REPO_ROOT = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from evaluation.dataset_b.full_ace_adapter import FullACEAdapter
adapter = FullACEAdapter()
# Try to get source of evaluate_sample
try:
    source = inspect.getsource(adapter.evaluate_sample)
    print(source[:2000])
except:
    pass
import inspect
try:
    source = inspect.getsource(adapter.evaluate_sample)
    print(source[:2000])
except:
    print("cannot get source")