fpath = r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine\tests\test_validation_agent.py'
with open(fpath, 'r') as f:
    content = f.read()

# Remove the old _determine_status tests and add correct ones based on the original method logic
# The original method uses score values (0.0 to 1.0), not execution_status

new_determine_status_tests = '''"""Test PASS when all scores >= 0.5 and sandbox available."\"\""""
    from app.agents.models import PatchValidationResult, ValidationStatus
    result = PatchValidationResult(patch_id='test', vulnerability_id='test')
    result.compilation_score.score = 1.0
    result.unit_test_score.score = 1.0
    result.regression_score.score = 1.0
    result.security_score.score = 1.0
    result.functional_score.score = 1.0
    result.performance_score.score = 1.0
    # All verified
    result.compilation_score.verified = True
    result.unit_test_score.verified = True
    result.regression_score.verified = True
    result.security_score.verified = True
    result.functional_score.verified = True
    result.performance_score.verified = True
    status = agent._determine_status(result, sandbox_available=True)
    assert status == ValidationStatus.PASS

def test_determine_status_all_unverified_when_sandbox_unavailable(agent):
    \"\"\"Test UNVERIFIED when sandbox unavailable and some dims unverified.\"\"\"
    from app.agents.models import PatchValidationResult, ValidationStatus
    result = PatchValidationResult(patch_id='test', vulnerability_id='test')
    result.compilation_score.score = 1.0
    result.unit_test_score.score = 1.0
    result.regression_score.score = 1.0
    result.security_score.score = 1.0
    result.functional_score.score = 1.0
    result.performance_score.score = 1.0
    # Mark unit tests as unverified
    result.unit_test_score.verified = False
    status = agent._determine_status(result, sandbox_available=False)
    assert status == ValidationStatus.UNVERIFIED

def test_determine_status_error_on_zero_score_with_errors(agent):
    \"\"\"Test ERROR when score is 0.0 and there are error strings.\"\"\"
    from app.agents.models import PatchValidationResult, ValidationStatus
    result = PatchValidationResult(patch_id='test', vulnerability_id='test')
    result.compilation_score.score = 0.0
    result.compilation_score.error = \"Compilation failed\"
    result.unit_test_score.score = 1.0
    result.regression_score.score = 1.0
    result.security_score.score = 1.0
    result.functional_score.score = 1.0
    result.performance_score.score = 1.0
    status = agent._determine_status(result, sandbox_available=True)
    assert status == ValidationStatus.ERROR

def test_determine_status_critical_security_fail(agent):
    \"\"\"Test FAIL when critical security vulnerabilities exist.\"\"\"
    from app.agents.models import PatchValidationResult, ValidationStatus
    result = PatchValidationResult(patch_id='test', vulnerability_id='test')
    result.security_score.critical = 1
    result.security_score.score = 1.0
    result.compilation_score.score = 1.0
    result.unit_test_score.score = 1.0
    result.regression_score.score = 1.0
    result.functional_score.score = 1.0
    result.performance_score.score = 1.0
    status = agent._determine_status(result, sandbox_available=True)
    assert status == ValidationStatus.FAIL

def test_determine_status_pass_min_score(agent):
    \"\"\"Test PASS when min score >= 0.5.\"\"\"
    from app.agents.models import PatchValidationResult, ValidationStatus
    result = PatchValidationResult(patch_id='test', vulnerability_id='test')
    # All scores exactly 0.5
    result.compilation_score.score = 0.5
    result.unit_test_score.score = 0.5
    result.regression_score.score = 0.5
    result.security_score.score = 0.5
    result.functional_score.score = 0.5
    result.performance_score.score = 0.5
    result.compilation_score.verified = True
    result.unit_test_score.verified = True
    result.regression_score.verified = True
    result.security_score.verified = True
    result.functional_score.verified = True
    result.performance_score.verified = True
    status = agent._determine_status(result, sandbox_available=True)
    assert status == ValidationStatus.PASS

def test_determine_status_warning_min_score(agent):
    \"\"\"Test WARNING when min score >= 0.3 but < 0.5.\"\"\"
    from app.agents.models import PatchValidationResult, ValidationStatus
    result = PatchValidationResult(patch_id='test', vulnerability_id='test')
    # Min score 0.4
    result.compilation_score.score = 1.0
    result.unit_test_score.score = 1.0
    result.regression_score.score = 1.0
    result.security_score.score = 0.4
    result.functional_score.score = 1.0
    result.performance_score.score = 1.0
    result.compilation_score.verified = True
    result.unit_test_score.verified = True
    result.regression_score.verified = True
    result.security_score.verified = True
    result.functional_score.verified = True
    result.performance_score.verified = True
    status = agent._determine_status(result, sandbox_available=True)
    assert status == ValidationStatus.WARNING

def test_determine_status_fail_below_threshold(agent):
    \"\"\"Test FAIL when min score < 0.3.\"\"\"
    from app.agents.models import PatchValidationResult, ValidationStatus
    result = PatchValidationResult(patch_id='test', vulnerability_id='test')
    # Min score 0.2
    result.compilation_score.score = 1.0
    result.unit_test_score.score = 1.0
    result.regression_score.score = 1.0
    result.security_score.score = 0.2
    result.functional_score.score = 1.0
    result.performance_score.score = 1.0
    result.compilation_score.verified = True
    result.unit_test_score.verified = True
    result.regression_score.verified = True
    result.security_score.verified = True
    result.functional_score.verified = True
    result.performance_score.verified = True
    status = agent._determine_status(result, sandbox_available=True)
    assert status == ValidationStatus.FAIL
'''

# Find the location of the old _determine_status tests and replace them
# The tests are at the end of the file

# First, let me find the exact line numbers
import re
# Find the test_determine_status section
match = re.search(r'def test_determine_status_all_pass\(agent\):.*?def test_determine_status_sandbox_unavailable\(agent\):.*', content, re.DOTALL)
if match:
    # Replace the section from test_determine_status_all_pass to the end
    start = match.start()
    end = len(content)
    content = content[:start] + new_determine_status_tests + '\n\n' + content[end:]
    
    with open(fpath, 'w') as f:
        f.write(content)
    print(' replaced _determine_status tests')
else:
    print('Could not find test section to replace')