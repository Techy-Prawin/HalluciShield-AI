import sys
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
from app.agents.sandbox_agent import SandboxAgent
from pathlib import Path
import json

agent = SandboxAgent()

# Test with a simple Python file
test_file = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\test_simple.py')
test_file.write_text('x = 1 + 2\nprint(f"result: {x}")')

try:
    result = agent.execute(
        code=str(test_file.read_text()),
        image=agent.image_name,
        timeout=30000,
    )
    print('Execution result:', json.dumps(result, indent=2)[:1000])
except Exception as e:
    print('Execution error:', type(e).__name__, e)