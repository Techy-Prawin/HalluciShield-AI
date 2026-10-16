import sys
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
from app.agents.validation_agent import ValidationAgent
import inspect
with open('/tmp/va_source.txt', 'w') as f:
    f.write(inspect.getsource(ValidationAgent.validate_candidate))