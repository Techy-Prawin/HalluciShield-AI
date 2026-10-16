import sys
from pathlib import Path
repo = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
sys.path.insert(0, str(repo))
sys.path.insert(0, str(repo / 'ai-engine'))
from app.agents.hallucination_agent import HallucinationDetectionAgent
import inspect

agent = HallucinationDetectionAgent()
print("HallucinationDetectionAgent methods:")
for attr in dir(agent):
    if not attr.startswith('__'):
        print(f"  {attr}")

# Check if there's an evaluate or analyze method
if hasattr(agent, 'evaluate'):
    print("\n evaluate method source (first 500):")
    try:
        src = inspect.getsource(agent.evaluate)
        print(src[:500])
    except Exception as e:
        print(f"Could not get source: {e}")
        
if hasattr(agent, 'analyze_security'):
    print("\n analyze_security method source (first 500):")
    try:
        src = inspect.getsource(agent.analyze_security)
        print(src[:500])
    except Exception as e:
        print(f"Could not get source: {e}")