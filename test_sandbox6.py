import sys
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
from app.agents.sandbox_agent import SandboxAgent
import inspect

agent = SandboxAgent()
# Get the source of _execute_pipeline
try:
    source = inspect.getsource(agent._execute_pipeline)
    print(source[:2000])
except Exception as e:
    print('Error getting source:', e)
    # Just print the method doc if available
    if agent._execute_pipeline.__doc__:
        print('Doc:', agent._execute_pipeline.__doc__[:500])