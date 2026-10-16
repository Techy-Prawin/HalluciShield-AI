fpath = r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine\tests\test_validation_agent.py'
with open(fpath, 'r') as f:
    lines = f.readlines()

# Append _determine_status tests
new_tests = """
def test_determine_status_all_pass(agent):
    \"\"\"Test PASS when all dimensions pass and are verified.\"\"\"
    from app.agents.models import ValidateCandidatesResult, ValidationStatus
    result = ValidateCandidatesResult(patch_id='test', vulnerability_id='test')
    result.compilation_score.execution_status = ValidationStatus.PASS
    result.compilation_score.verified = True
    result.unit_test_score.execution_status = ValidationStatus.PASS
    result.unit_test_score.verified = True
    result.regression_score.execution_status = ValidationStatus.PASS
    result.regression_score.verified = True
    result.security_score.execution_status = ValidationStatus.PASS
    result.security_score.verified = True
    result.functional_score.execution_status = ValidationStatus.PASS
    result.functional_score.verified = True
    result.performance_score.execution_status = ValidationStatus.PASS
    result.performance_score.verified = True
    status = agent._determine_status(result, sandbox_available=True)
    assert status == ValidationStatus.PASS

def test_determine_status_unit_test_unverified(agent):
    \"\"\"Test UNVERIFIED when unit tests are unverified.\"\"\"
    from app.agents.models import ValidateCandidatesResult, ValidationStatus
    result = ValidateCandidatesResult(patch_id='test', vulnerability_id='test')
    result.unit_test_score.execution_status = ValidationStatus.UNVERIFIED
    result.unit_test_score.verified = False
    status = agent._determine_status(result, sandbox_available=True)
    assert status == ValidationStatus.UNVERIFIED

def test_determine_status_functional_unverified(agent):
    \"\"\"Test UNVERIFIED when functional behavior is unverified.\"\"\"
    from app.agents.models import ValidateCandidatesResult, ValidationStatus
    result = ValidateCandidatesResult(patch_id='test', vulnerability_id='test')
    result.functional_score.execution_status = ValidationStatus.UNVERIFIED
    result.functional_score.verified = False
    status = agent._determine_status(result, sandbox_available=True)
    assert status == ValidationStatus.UNVERIFIED

def test_determine_status_compilation_error(agent):
    \"\"\"Test ERROR when compilation has error.\"\"\"
    from app.agents.models import ValidateCandidatesResult, ValidationStatus
    result = ValidateCandidatesResult(patch_id='test', vulnerability_id='test')
    result.compilation_score.execution_status = ValidationStatus.ERROR
    status = agent._determine_status(result, sandbox_available=True)
    assert status == ValidationStatus.ERROR

def test_determine_status_compilation_fail(agent):
    \"\"\"Test FAIL when compilation fails.\"\"\"
    from app.agents.models import ValidateCandidatesResult, ValidationStatus
    result = ValidateCandidatesResult(patch_id='test', vulnerability_id='test')
    result.compilation_score.execution_status = ValidationStatus.FAIL
    status = agent._determine_status(result, sandbox_available=True)
    assert status == ValidationStatus.FAIL

def test_determine_status_critical_security(agent):
    \"\"\"Test FAIL when critical security vulnerabilities exist.\"\"\"
    from app.agents.models import ValidateCandidatesResult, ValidationStatus
    result = ValidateCandidatesResult(patch_id='test', vulnerability_id='test')
    result.security_score.vulnerabilities_found = 1
    result.security_score.critical = 1
    result.security_score.execution_status = ValidationStatus.PASS
    result.security_score.verified = True
    status = agent._determine_status(result, sandbox_available=True)
    assert status == ValidationStatus.FAIL

def test_determine_status_sandbox_unavailable(agent):
    \"\"\"Test UNVERIFIED when sandbox unavailable.\"\"\"
    from app.agents.models import ValidateCandidatesResult, ValidationStatus
    result = ValidateCandidatesResult(patch_id='test', vulnerability_id='test')
    result.compilation_score.execution_status = ValidationStatus.PASS
    result.compilation_score.verified = True
    result.unit_test_score.execution_status = ValidationStatus.PASS
    result.unit_test_score.verified = True
    result.regression_score.execution_status = ValidationStatus.PASS
    result.regression_score.verified = True
    result.security_score.execution_status = ValidationStatus.PASS
    result.security_score.verified = True
    result.functional_score.execution_status = ValidationStatus.PASS
    result.functional_score.verified = True
    result.performance_score.execution_status = ValidationStatus.PASS
    result.performance_score.verified = True
    status = agent._determine_status(result, sandbox_available=False)
    assert status == ValidationStatus.UNVERIFIED
"""

with open(fpath, 'a') as f:
    f.write(new_tests)

print('Added _determine_status tests')