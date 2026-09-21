"""
Test dataset part 2: JWT, AUTH, HALLUCINATED_API, HALLUCINATED_PKG.
"""
from app.agents.models import TestCase, VulnerabilityTestCategory


_JWT = [
    TestCase(test_id='JWT-001', vuln_category=VulnerabilityTestCategory.INSECURE_JWT,
        vulnerability_type='INSECURE_JWT', severity='CRITICAL', file_path='app/auth/jwt_handler.py',
        original_code='payload = jwt.decode(token, options={"verify_signature": False})',
        vulnerable_line=1, description='JWT signature verification disabled', cwe='CWE-347'),
    TestCase(test_id='JWT-002', vuln_category=VulnerabilityTestCategory.INSECURE_JWT,
        vulnerability_type='INSECURE_JWT', severity='CRITICAL', file_path='app/auth/jwt_handler.py',
        original_code='payload = jwt.decode(token, "weak_secret")',
        vulnerable_line=1, description='Weak JWT signing secret', cwe='CWE-347'),
    TestCase(test_id='JWT-003', vuln_category=VulnerabilityTestCategory.INSECURE_JWT,
        vulnerability_type='INSECURE_JWT', severity='HIGH', file_path='app/auth/session.py',
        original_code='token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")',
        vulnerable_line=1, description='Weak HMAC algorithm for JWT', cwe='CWE-347'),
    TestCase(test_id='JWT-004', vuln_category=VulnerabilityTestCategory.INSECURE_JWT,
        vulnerability_type='INSECURE_JWT', severity='CRITICAL', file_path='app/auth/refresh.py',
        original_code='decoded = jwt.decode(refresh_token, SECRET_KEY, algorithms=["none"])',
        vulnerable_line=1, description='Algorithm None accepted in JWT', cwe='CWE-347'),
    TestCase(test_id='JWT-005', vuln_category=VulnerabilityTestCategory.INSECURE_JWT,
        vulnerability_type='INSECURE_JWT', severity='HIGH', file_path='app/auth/claims.py',
        original_code='claims = jwt.decode(token, SECRET_KEY, options={"verify_exp": False})',
        vulnerable_line=1, description='JWT expiration not verified', cwe='CWE-347'),
]

_AUTH = [
    TestCase(test_id='AUTH-001', vuln_category=VulnerabilityTestCategory.AUTH_FLAW,
        vulnerability_type='AUTH_FLAW', severity='HIGH', file_path='app/auth/login.py',
        original_code='if password == stored_password: login(user)',
        vulnerable_line=1, description='Plaintext password comparison', cwe='CWE-256'),
    TestCase(test_id='AUTH-002', vuln_category=VulnerabilityTestCategory.AUTH_FLAW,
        vulnerability_type='AUTH_FLAW', severity='CRITICAL', file_path='app/auth/reset.py',
        original_code='reset_token = str(random.randint(100000, 999999))',
        vulnerable_line=1, description='Predictable reset token from random', cwe='CWE-330'),
    TestCase(test_id='AUTH-003', vuln_category=VulnerabilityTestCategory.AUTH_FLAW,
        vulnerability_type='AUTH_FLAW', severity='HIGH', file_path='app/auth/register.py',
        original_code='hash = md5(password.encode()).hexdigest()',
        vulnerable_line=1, description='MD5 for password hashing', cwe='CWE-328'),
    TestCase(test_id='AUTH-004', vuln_category=VulnerabilityTestCategory.AUTH_FLAW,
        vulnerability_type='AUTH_FLAW', severity='CRITICAL', file_path='app/auth/admin.py',
        original_code="if request.headers.get('X-Admin') == 'true': grant_admin()",
        vulnerable_line=1, description='Client-controlled admin flag in header', cwe='CWE-287'),
    TestCase(test_id='AUTH-005', vuln_category=VulnerabilityTestCategory.AUTH_FLAW,
        vulnerability_type='AUTH_FLAW', severity='HIGH', file_path='app/auth/mfa.py',
        original_code="otp = ''.join([str(random.randint(0,9)) for _ in range(6)])",
        vulnerable_line=1, description='Non-cryptographic OTP generation', cwe='CWE-330'),
]

_HAPI = [
    TestCase(test_id='HAPI-001', vuln_category=VulnerabilityTestCategory.HALLUCINATED_API,
        vulnerability_type='HALLUCINATED_API', severity='HIGH', file_path='app/services/payment.py',
        original_code="stripe.api_key = 'sk_live_fake_key'\nstripe.Charges.create(amount=100)",
        vulnerable_line=1, description='Hallucinated Stripe Charges API (should be PaymentIntents)', cwe='CWE-706'),
    TestCase(test_id='HAPI-002', vuln_category=VulnerabilityTestCategory.HALLUCINATED_API,
        vulnerability_type='HALLUCINATED_API', severity='HIGH', file_path='app/services/email.py',
        original_code='sendgrid.client.send(message)',
        vulnerable_line=1, description='Hallucinated sendgrid.client API', cwe='CWE-706'),
    TestCase(test_id='HAPI-003', vuln_category=VulnerabilityTestCategory.HALLUCINATED_API,
        vulnerability_type='HALLUCINATED_API', severity='MEDIUM', file_path='app/services/storage.py',
        original_code="s3 = boto3.resource('s3'); bucket = s3.Bucket('my-bucket')",
        vulnerable_line=1, description='Deprecated S3 resource interface', cwe='CWE-706'),
    TestCase(test_id='HAPI-004', vuln_category=VulnerabilityTestCategory.HALLUCINATED_API,
        vulnerability_type='HALLUCINATED_API', severity='HIGH', file_path='app/services/auth.py',
        original_code='requests_oauth2.Client(client_id, client_secret)',
        vulnerable_line=1, description='Hallucinated requests_oauth2 API', cwe='CWE-706'),
    TestCase(test_id='HAPI-005', vuln_category=VulnerabilityTestCategory.HALLUCINATED_API,
        vulnerability_type='HALLUCINATED_API', severity='MEDIUM', file_path='app/services/db.py',
        original_code="pymongo.MongoClient().db.command('aggregate', pipeline)",
        vulnerable_line=1, description='Incorrect pymongo command API usage', cwe='CWE-706'),
]

_HPKG = [
    TestCase(test_id='HPKG-001', vuln_category=VulnerabilityTestCategory.HALLUCINATED_PACKAGE,
        vulnerability_type='HALLUCINATED_PACKAGE', severity='HIGH', file_path='app/utils/crypto.py',
        original_code='from cryptolib import encrypt; encrypted = encrypt(data, key)',
        vulnerable_line=1, description='Non-existent cryptolib package', cwe='CWE-1395'),
    TestCase(test_id='HPKG-002', vuln_category=VulnerabilityTestCategory.HALLUCINATED_PACKAGE,
        vulnerability_type='HALLUCINATED_PACKAGE', severity='HIGH', file_path='app/utils/hash_utils.py',
        original_code='from hashlib_utils import secure_hash; h = secure_hash(data)',
        vulnerable_line=1, description='Non-existent hashlib_utils package', cwe='CWE-1395'),
    TestCase(test_id='HPKG-003', vuln_category=VulnerabilityTestCategory.HALLUCINATED_PACKAGE,
        vulnerability_type='HALLUCINATED_PACKAGE', severity='MEDIUM', file_path='app/utils/validation.py',
        original_code='from validlib import validate_email; valid = validate_email(email)',
        vulnerable_line=1, description='Non-existent validlib package', cwe='CWE-1395'),
    TestCase(test_id='HPKG-004', vuln_category=VulnerabilityTestCategory.HALLUCINATED_PACKAGE,
        vulnerability_type='HALLUCINATED_PACKAGE', severity='HIGH', file_path='app/utils/encryption.py',
        original_code='from aes_crypto import AESCipher; cipher = AESCipher(key)',
        vulnerable_line=1, description='Non-existent aes_crypto package', cwe='CWE-1395'),
    TestCase(test_id='HPKG-005', vuln_category=VulnerabilityTestCategory.HALLUCINATED_PACKAGE,
        vulnerability_type='HALLUCINATED_PACKAGE', severity='MEDIUM', file_path='app/utils/uuid_gen.py',
        original_code='from uuid_utils import generate_uuid; uid = generate_uuid()',
        vulnerable_line=1, description='Non-existent uuid_utils package (uuid4 exists in stdlib)', cwe='CWE-1395'),
]


JWT_TEST_CASES = _JWT
AUTH_TEST_CASES = _AUTH
HAPI_TEST_CASES = _HAPI
HPKG_TEST_CASES = _HPKG
