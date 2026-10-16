import sys
from pathlib import Path
repo = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
sys.path.insert(0, str(repo))
sys.path.insert(0, str(repo / 'ai-engine'))
from app.agents.dependency_agent import DependencyAnalysisAgent
import inspect

agent = DependencyAnalysisAgent()
print("DependencyAnalysisAgent methods:")
for attr in dir(agent):
    if not attr.startswith('__'):
        print(f"  {attr}")

# Check if there's a method that could return NOT_AVAILABLE
if hasattr(agent, 'is_available'):
    print("\n is_available method:")
    try:
        src = inspect.getsource(agent.is_available)
        print(src[:500])
    except:
        print("Could not get source")

if hasattr(agent, 'analyze'):
    print("\n analyze method:")
    try:
        src = inspect.getsource(agent.analyze)
        print(src[:500])
    except:
        print("Could not get source")