import sys
from pathlib import Path
repo = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
sys.path.insert(0, str(repo))
sys.path.insert(0, str(repo / 'ai-engine'))
from app.agents.dependency_agent import DependencyAnalysisAgent
import inspect

agent = DependencyAnalysisAgent()

# Check analyze_dependencies method
if hasattr(agent, 'analyze_dependencies'):
    print("=== analyze_dependencies ===")
    src = inspect.getsource(agent.analyze_dependencies)
    print(src[:1500])