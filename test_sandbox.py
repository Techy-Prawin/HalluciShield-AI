import sys
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
from app.agents.sandbox_agent import SandboxAgent
import json

agent = SandboxAgent()
print('SandboxAgent created')
print('Docker available:', agent.docker_available)
print('Sandbox status:', agent.sandbox_status)