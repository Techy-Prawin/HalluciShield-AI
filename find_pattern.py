fpath = r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\frontend/components/command/HeroWorkflow.tsx'
with open(fpath, 'r') as f:
    content = f.read()
# Find the section with artifactAuthorization
idx = content.find("artifactAuthorization === 'AUTHORIZED'")
if idx >= 0:
    start = max(0, idx - 30)
    end = min(len(content), idx + 200)
    print('Found at index', idx)
    print('Context:')
    print(content[start:end])
else:
    print('Not found')