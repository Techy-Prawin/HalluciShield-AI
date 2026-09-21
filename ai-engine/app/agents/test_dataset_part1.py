"""
Test dataset part: SQL, XSS, CMD, PATH, SECRETS.
"""
from app.agents.models import TestCase, VulnerabilityTestCategory


_SQL = [
    TestCase(test_id='SQL-001', vuln_category=VulnerabilityTestCategory.SQL_INJECTION,
        vulnerability_type='CROSS_SITE_SCRIPTING', severity='CRITICAL', file_path='app/db/users.py',
        original_code="cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
        vulnerable_line=1, description='Direct string concatenation in SQL query', cwe='CWE-89'),
    TestCase(test_id='SQL-002', vuln_category=VulnerabilityTestCategory.SQL_INJECTION,
        vulnerability_type='CROSS_SITE_SCRIPTING', severity='CRITICAL', file_path='app/db/orders.py',
        original_code='query = f"DELETE FROM orders WHERE order_id = {order_id}"; cursor.execute(query)',
        vulnerable_line=1, description='F-string interpolation in SQL DELETE', cwe='CWE-89'),
    TestCase(test_id='SQL-003', vuln_category=VulnerabilityTestCategory.SQL_INJECTION,
        vulnerability_type='CROSS_SITE_SCRIPTING', severity='HIGH', file_path='app/db/search.py',
        original_code="sql = 'SELECT * FROM products WHERE name LIKE %' + search_term + '%'",
        vulnerable_line=1, description='String concatenation in LIKE clause', cwe='CWE-89'),
    TestCase(test_id='SQL-004', vuln_category=VulnerabilityTestCategory.SQL_INJECTION,
        vulnerability_type='CROSS_SITE_SCRIPTING', severity='CRITICAL', file_path='app/db/auth.py',
        original_code="cursor.execute('UPDATE users SET role=' + new_role + ' WHERE id=' + uid)",
        vulnerable_line=1, description='String concat in UPDATE statement', cwe='CWE-89'),
    TestCase(test_id='SQL-005', vuln_category=VulnerabilityTestCategory.SQL_INJECTION,
        vulnerability_type='CROSS_SITE_SCRIPTING', severity='HIGH', file_path='app/db/logs.py',
        original_code="cursor.execute('INSERT INTO logs(msg) VALUES(' + msg + ')')",
        vulnerable_line=1, description='String concat in INSERT VALUES', cwe='CWE-89'),
]

_XSS = [
    TestCase(test_id='XSS-001', vuln_category=VulnerabilityTestCategory.XSS,
        vulnerability_type='CROSS_SITE_SCRIPTING', severity='HIGH', file_path='app/views/profile.py',
        original_code='return f"<h1>Welcome {username}</h1>"',
        vulnerable_line=1, description='Unescaped user input in HTML response', cwe='CWE-79'),
    TestCase(test_id='XSS-002', vuln_category=VulnerabilityTestCategory.XSS,
        vulnerability_type='CROSS_SITE_SCRIPTING', severity='HIGH', file_path='app/views/comments.py',
        original_code="html = '<div class=comment>' + comment_body + '</div>'",
        vulnerable_line=1, description='Raw HTML injection via comment body', cwe='CWE-79'),
    TestCase(test_id='XSS-003', vuln_category=VulnerabilityTestCategory.XSS,
        vulnerability_type='CROSS_SITE_SCRIPTING', severity='MEDIUM', file_path='app/views/search.py',
        original_code='return f"<p>Results for: {query}</p>"',
        vulnerable_line=1, description='Unescaped search query in response', cwe='CWE-79'),
    TestCase(test_id='XSS-004', vuln_category=VulnerabilityTestCategory.XSS,
        vulnerability_type='CROSS_SITE_SCRIPTING', severity='HIGH', file_path='app/views/error.py',
        original_code='return f"<div class=error>{error_msg}</div>"',
        vulnerable_line=1, description='Error message reflected in HTML without escaping', cwe='CWE-79'),
    TestCase(test_id='XSS-005', vuln_category=VulnerabilityTestCategory.XSS,
        vulnerability_type='CROSS_SITE_SCRIPTING', severity='MEDIUM', file_path='app/views/redirect.py',
        original_code='return redirect(f"/next?name={user_name}")',
        vulnerable_line=1, description='Unescaped parameter in redirect URL', cwe='CWE-79'),
]

_CMD = [
    TestCase(test_id='CMD-001', vuln_category=VulnerabilityTestCategory.COMMAND_INJECTION,
        vulnerability_type='COMMAND_INJECTION', severity='CRITICAL', file_path='app/utils/ping.py',
        original_code='os.system("ping -c 4 " + host)',
        vulnerable_line=1, description='Direct OS command with user input', cwe='CWE-78'),
    TestCase(test_id='CMD-002', vuln_category=VulnerabilityTestCategory.COMMAND_INJECTION,
        vulnerability_type='COMMAND_INJECTION', severity='CRITICAL', file_path='app/utils/dns.py',
        original_code='result = subprocess.call("nslookup " + domain, shell=True)',
        vulnerable_line=1, description='Shell=True with user-controlled domain', cwe='CWE-78'),
    TestCase(test_id='CMD-003', vuln_category=VulnerabilityTestCategory.COMMAND_INJECTION,
        vulnerability_type='COMMAND_INJECTION', severity='HIGH', file_path='app/utils/files.py',
        original_code='os.popen("cat " + filepath).read()',
        vulnerable_line=1, description='os.popen with user-controlled filepath', cwe='CWE-78'),
    TestCase(test_id='CMD-004', vuln_category=VulnerabilityTestCategory.COMMAND_INJECTION,
        vulnerability_type='COMMAND_INJECTION', severity='CRITICAL', file_path='app/utils/proc.py',
        original_code='os.system("kill " + signal + " " + pid)',
        vulnerable_line=1, description='OS command with two user-controlled args', cwe='CWE-78'),
    TestCase(test_id='CMD-005', vuln_category=VulnerabilityTestCategory.COMMAND_INJECTION,
        vulnerability_type='COMMAND_INJECTION', severity='HIGH', file_path='app/utils/archive.py',
        original_code='subprocess.run(f"tar czf /tmp/out.tar.gz {dirname}", shell=True)',
        vulnerable_line=1, description='F-string in shell command with shell=True', cwe='CWE-78'),
]

_PATH = [
    TestCase(test_id='PATH-001', vuln_category=VulnerabilityTestCategory.PATH_TRAVERSAL,
        vulnerability_type='PATH_TRAVERSAL', severity='HIGH', file_path='app/views/download.py',
        original_code='open(os.path.join("/data/files", user_filename)).read()',
        vulnerable_line=1, description='Unsanitized filename in path join', cwe='CWE-22'),
    TestCase(test_id='PATH-002', vuln_category=VulnerabilityTestCategory.PATH_TRAVERSAL,
        vulnerability_type='PATH_TRAVERSAL', severity='HIGH', file_path='app/views/template.py',
        original_code="path = '/templates/' + template_name; content = open(path).read()",
        vulnerable_line=1, description='Concatenated path with user template name', cwe='CWE-22'),
    TestCase(test_id='PATH-003', vuln_category=VulnerabilityTestCategory.PATH_TRAVERSAL,
        vulnerability_type='PATH_TRAVERSAL', severity='MEDIUM', file_path='app/views/export.py',
        original_code="filepath = f'/exports/{user_dir}/report.csv'; return send_file(filepath)",
        vulnerable_line=1, description='F-string path with user-controlled directory', cwe='CWE-22'),
    TestCase(test_id='PATH-004', vuln_category=VulnerabilityTestCategory.PATH_TRAVERSAL,
        vulnerability_type='PATH_TRAVERSAL', severity='HIGH', file_path='app/views/backup.py',
        original_code='shutil.copytree(src="/backups/" + backup_name, dst="/restore")',
        vulnerable_line=1, description='User input in copytree source path', cwe='CWE-22'),
    TestCase(test_id='PATH-005', vuln_category=VulnerabilityTestCategory.PATH_TRAVERSAL,
        vulnerability_type='PATH_TRAVERSAL', severity='HIGH', file_path='app/views/log_viewer.py',
        original_code='with open("/var/log/" + log_file) as f: return f.readlines()',
        vulnerable_line=1, description='Log file path concatenation', cwe='CWE-22'),
]

_SECRET = [
    TestCase(test_id='SECRET-001', vuln_category=VulnerabilityTestCategory.HARDCODED_SECRETS,
        vulnerability_type='HARDCODED_SECRET', severity='CRITICAL', file_path='app/config/db.py',
        original_code='DB_PASSWORD = "super_secret_123!"',
        vulnerable_line=1, description='Hardcoded database password', cwe='CWE-798'),
    TestCase(test_id='SECRET-002', vuln_category=VulnerabilityTestCategory.HARDCODED_SECRETS,
        vulnerability_type='HARDCODED_SECRET', severity='CRITICAL', file_path='app/config/api_keys.py',
        original_code='STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"',
        vulnerable_line=1, description='Hardcoded Stripe API key', cwe='CWE-798'),
    TestCase(test_id='SECRET-003', vuln_category=VulnerabilityTestCategory.HARDCODED_SECRETS,
        vulnerability_type='HARDCODED_SECRET', severity='HIGH', file_path='app/auth/jwt.py',
        original_code='JWT_SECRET = "my-jwt-signing-key-2024"',
        vulnerable_line=1, description='Hardcoded JWT signing secret', cwe='CWE-798'),
    TestCase(test_id='SECRET-004', vuln_category=VulnerabilityTestCategory.HARDCODED_SECRETS,
        vulnerability_type='HARDCODED_SECRET', severity='CRITICAL', file_path='app/config/aws.py',
        original_code='AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"',
        vulnerable_line=1, description='Hardcoded AWS secret access key', cwe='CWE-798'),
    TestCase(test_id='SECRET-005', vuln_category=VulnerabilityTestCategory.HARDCODED_SECRETS,
        vulnerability_type='HARDCODED_SECRET', severity='HIGH', file_path='app/config/email.py',
        original_code='SMTP_PASSWORD = "email_pass_456"',
        vulnerable_line=1, description='Hardcoded SMTP password', cwe='CWE-798'),
]


SQL_TEST_CASES = _SQL
XSS_TEST_CASES = _XSS
CMD_TEST_CASES = _CMD
PATH_TEST_CASES = _PATH
SECRET_TEST_CASES = _SECRET
