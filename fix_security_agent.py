import sys
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')

# Read the current file
with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine\app\agents\security_agent.py', 'r') as f:
    content = f.read()

# The fix: replace the RuntimeError raise with a return of SecurityAnalysisResponse
old_code = """            if scan_status in ("FAILED", "TIMEOUT"):
                err_msg = scan_metadata.get("error", f"Scanner status {scan_status}")
                logger.error(f"[SecurityAgent] Scan {scan_status}: {err_msg}")
                raise RuntimeError(f"Security scanner {scan_status}: {err_msg}")"""

new_code = """            if scan_status in ("FAILED", "TIMEOUT"):
                err_msg = scan_metadata.get("error", f"Scanner status {scan_status}")
                logger.error(f"[SecurityAgent] Scan {scan_status}: {err_msg}")
                # Return empty response instead of raising RuntimeError.
                # This allows the pipeline to continue with NOT_APPLICABLE evidence;
                # a timeout never becomes a negative prediction.
                return SecurityAnalysisResponse(
                    repository_id=repository_id,
                    total_vulnerabilities=0,
                    critical_count=0,
                    high_count=0,
                    medium_count=0,
                    low_count=0,
                    findings=[],
                    scan_duration_ms=int((time.time() - start_time) * 1000),
                    status="NOT_APPLICABLE",
                    error=err_msg,
                )"""

if old_code in content:
    fixed_content = content.replace(old_code, new_code)
    with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine\app\agents\security_agent.py', 'w') as f:
        f.write(fixed_content)
    print('Fix applied successfully')
else:
    print('Old code not found - source may have changed')
    # Show what we're looking for
    import re
    match = re.search(r'if scan_status in.*?raise RuntimeError', content, re.DOTALL)
    if match:
        print(f'Found similar pattern: {match.group()[:200]}')