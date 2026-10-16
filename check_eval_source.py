import sys
from pathlib import Path
repo = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
sys.path.insert(0, str(repo))
sys.path.insert(0, str(repo / 'ai-engine'))
from evaluation.dataset_b.full_ace_adapter import FullACEAdapter
import inspect
adapter = FullACEAdapter()
try:
    src = inspect.getsource(adapter.evaluate_sample)
    # Print the first 8000 chars
    print(src[:8000])
except Exception as e:
    print(f"Error: {e}")
    # Try alternative
    print("Trying alternative source retrieval...")
    # Check if evaluate_sample has a docstring
    print(f"Docstring: {adapter.evaluate_sample.__doc__[:500] if adapter.evaluate_sample.__doc__ else 'No docstring'}")