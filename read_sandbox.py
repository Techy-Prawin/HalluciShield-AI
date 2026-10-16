with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine\app\agents\sandbox_agent.py', 'r') as f:
    lines = f.readlines()
    for i, line in enumerate(lines[75:95], start=76):
        print(f"{i}: {line}", end='')