import sys
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
from app.agents.sandbox_agent import SandboxAgent
agent = SandboxAgent()
print('is_available:', agent.is_available)
print('image_name:', agent.image_name)
print('_docker:', agent._docker)