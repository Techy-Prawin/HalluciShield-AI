import sys
import inspect
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
from app.agents.sandbox_agent import SandboxAgent
agent = SandboxAgent()
# Get the source of _create_container
try:
    source = inspect.getsource(agent._create_container)
    print('_create_container first 2000 chars:')
    print(source[:2000])
except Exception as e:
    print('Error:', e)