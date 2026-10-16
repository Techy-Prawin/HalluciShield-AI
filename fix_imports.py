fpath = r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine\tests\test_validation_agent.py'
with open(fpath, 'r') as f:
    content = f.read()

# Replace ValidateCandidatesResult with PatchValidationResult in the _determine_status tests
content = content.replace(
    'from app.agents.models import ValidateCandidatesResult, ValidationStatus',
    'from app.agents.models import PatchValidationResult, ValidationStatus'
)

with open(fpath, 'w') as f:
    f.write(content)

print('Updated imports in _determine_status tests')