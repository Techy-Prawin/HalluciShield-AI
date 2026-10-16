import sys
from pathlib import Path
repo = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
sys.path.insert(0, str(repo))
sys.path.insert(0, str(repo / 'ai-engine'))
from app.agents.hallucination_agent import HallucinationDetectionAgent
import inspect

agent = HallucinationDetectionAgent()

# Check detect_hallucinations method
if hasattr(agent, 'detect_hallucinations'):
    print("=== detect_hallucinations ===")
    src = inspect.getsource(agent.detect_hallucinations)
    print(src[:1000])

# Check analyzer method
if hasattr(agent, 'analyzer'):
    print("\n=== analyzer ===")
    # Try to get source or just check what it is
    print(f"Type: {type(agent.analyzer)}")
    if hasattr(agent.analyzer, '__call__'):
        src = inspect.getsource(agent.analyzer.__call__)
        print(src[:500])