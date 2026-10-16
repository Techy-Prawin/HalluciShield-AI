fpath = r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine\tests\test_validation_agent.py'
with open(fpath, 'r') as f:
    lines = f.readlines()

# The _determine_status tests should use PatchValidationResult and follow the original method logic
# Append at the end of the file

test_code = '''

def test_determine_status_all_pass(agent):
    \"\"\"Test PASS when all scores >= 0.5.\"\"\"
    from app.agents.models import PatchValidationResult, ValidationStatus
    result = PatchValidationResult(patch_id='test', vulnerability_id='test')
    result.compilation_score.score = 1.0
    result.unit_test_score.score = 1.0
    result.regression_score.score = 1.0
    result.security_score.score = 1.0
    result.functional_score.score = 1.0
    result.performance_score.score = 1.0
    result.compilation_score.verified = True
    result.unit_test_score.verified = True
    result.regression_score.verified = True
    result.security_score.verified = True
    result.functional_score.verified = True
    result.performance_score.verified = True
    status = agent._determine_status(result, sandbox_available=True)
    assert status == ValidationStatus.PASS

def test_determine_status_unverified_when_sandbox_unavailable(agent):
    \"\"\"Test UNVERIFIED when sandbox unavailable and dims unverified.\"\"\"
    from app.agents.models import PatchValidationResult, ValidationStatus
    result = PatchValidationResult(patch_id='test', vulnerability_id='test')
    result.compilation_score.score = 1.0
    result.unit_test_score.score = 1.0
    result.regression_score.score = 1.0
    result.security_score.score = 1.0
    result.functional_score.score = 1.0
    result.performance_score.score = 1.0
    result.unit_test_score.verified = False
    status = agent._determine_status(result, sandbox_available=False)
    assert status == ValidationStatus.UNVERIFIED

def test_determine_status_error_on_zero_score_with_errors(agent):
    \"\"\"Test ERROR when score is 0.0 and has error strings.\"\"\"
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

# Append the tests
with open(fpath, 'a') as f:
    f.write(test_code)

print('Appended _determine_status tests successfully')