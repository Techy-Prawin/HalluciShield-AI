fpath = r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine\app\agents\validation_agent.py'
with open(fpath, 'r') as f:
    content = f.read()

# Fix _score_performance - add 4 spaces before 'def'
# The current has 'def _score_performance(' at the start of line 722 with no indentation
# We need '    def _score_performance(' with 4 spaces

# Replace the pattern
content = content.replace(
    'def _score_performance(\n        self,', 
    '    def _score_performance(\n        self,'
)

with open(fpath, 'w') as f:
    f.write(content)

print('Fixed _score_performance indentation')