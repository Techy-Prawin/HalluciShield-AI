import sys
from pathlib import Path
repo = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
sys.path.insert(0, str(repo))
sys.path.insert(0, str(repo / 'ai-engine'))
from evaluation.dataset_b.full_ace_adapter import FullACEAdapter

# Check if adapter has any configuration or mode settings
adapter = FullACEAdapter()

# Look at the __init__ method source
try:
    src = inspect.getsource(FullACEAdapter.__init__)
    print("FullACEAdapter.__init__ source:")
    print(src[:2000])
except:
    print("Could not get __init__ source")

# Check for any configuration attributes
print("\nAdapter __dict__ keys:")
if hasattr(adapter, '__dict__'):
    for k, v in adapter.__dict__.items():
        if not k.startswith('_') or k in ('_docker', '_sandbox_available', 'evaluation_mode'):
            print(f"  {k}: {type(v).__name__} = {v}")
else:
    print("No __dict__")