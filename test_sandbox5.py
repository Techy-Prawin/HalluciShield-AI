import sys
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
from app.agents.sandbox_agent import SandboxAgent
agent = SandboxAgent()
print('Available methods:')
for method in dir(agent):
    if not method.startswith('_') or method in ['_execute_pipeline', 'is_available', 'validate_patch', 'validate_patches_batch']:
        print('  ', method)
# Check _execute_pipeline
if hasattr(agent, '_execute_pipeline'):
    print('_execute_pipeline signature check')