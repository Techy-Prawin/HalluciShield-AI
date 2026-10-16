#!/usr/bin/env python3
"""Final ACE failure analysis."""
with open("evaluation/dataset_b/evaluator.py") as f:
    lines = f.readlines()

print("=== ACE except block (lines 906-914) ===")
for i in range(905, 915):
    print(f"{i+1:4d}: {lines[i]}", end="")

print()
print("Key facts:")
print("  1. The try: block at line 731 imports app.agents.orchestration.service")
print("  2. This module does NOT exist in ai-engine/app/agents/")
print("  3. ImportError fires at line 738 -> caught by except at 906")
print("  4. detected=False, prediction=negative -> ALL 500 = FAILED")
print("  5. The pattern-based fallback (lines 764-903) is NEVER reached")
print("  6. traceback.print_exc() was called, so errors were printed to stderr")
print("  7. But they were silently swallowed by the evaluator")

print()
print("=== Summary of all 4 system failures ===")
print()
print("A. Semgrep:")
print("   - Called agent.analyze_security(workspace_path=str(fp))")
print("   - `fp` is a SINGLE FILE PATH, not a directory")
print("   - Semgrep is available? Let us check...")
import shutil
semgrep = shutil.which("semgrep")
print(f"   - shutil.which('semgrep') = {semgrep}")
if semgrep:
    import subprocess
    r = subprocess.run([semgrep, "--version"], capture_output=True, text=True, timeout=10)
    print(f"   - semgrep version check: rc={r.returncode} stdout={r.stdout.strip()}")
else:
    print("   - Semgrep NOT available -> fallback_scan() is called")
    print("   - fallback_scan() does os.walk(target_path)")
    print("   - os.walk(FILE) yields NOTHING")
    print("   - BUG: 0 findings for every single-file scan")

print()
print("B. LLM:")
print("   - for loop iterates all 500 samples, building prompt for each")
print("   - BUT the API call is at indentation level 4 (function body), NOT inside the loop")
print("   - Prompt gets overwritten 500 times; only the LAST sample's prompt is sent")
print("   - Only 1 API call is made, producing 1 record instead of 500")
print("   - No API key was set -> no_api_key branch")
print("   - Only 1 record is appended to results")

print()
print("C. Sandbox:")
print("   - Files exist and are found correctly")
print("   - Python sandbox tries to run ALL files (Go, Java, JS, etc.) as Python")
print("   - 481 files fail with SyntaxError -> status=ERROR -> predicted=negative")
print("   - 18 Python files run to completion with empty stdout/stderr")
print("   - Vuln detection uses keywords in stdout/stderr: none appear")
print("   - 0 positives detected")
print("   - No vulnerability oracle: sandbox cannot tell if code IS vulnerable")

print()
print("D. Full HalluciShield ACE:")
print("   - Tries to import app.agents.orchestration.service")
print("   - Module DOES NOT EXIST")
print("   - ImportError for all 500 samples -> predicted=negative")
print("   - The real ACE pipeline NEVER ran for any sample")
