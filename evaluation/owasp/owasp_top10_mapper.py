"""OWASP Top 10 (2021) Mapping Layer.

Provides rigorous, standard-aligned mapping from Common Weakness Enumeration (CWE)
identifiers to OWASP Top 10:2021 categories.

Rule:
- Mappings adhere to official OWASP Top 10:2021 definitions.
- CWEs not explicitly defined under any OWASP category map to "UNMAPPED".
- Clearly distinguishes between OWASP Top 10 categorization and the OWASP Benchmark Project.
"""

from typing import Dict, List, Optional, Tuple, Any

# Official OWASP Top 10:2021 categories
OWASP_TOP10_2021: Dict[str, str] = {
    "A01": "A01:2021-Broken Access Control",
    "A02": "A02:2021-Cryptographic Failures",
    "A03": "A03:2021-Injection",
    "A04": "A04:2021-Insecure Design",
    "A05": "A05:2021-Security Misconfiguration",
    "A06": "A06:2021-Vulnerable and Outdated Components",
    "A07": "A07:2021-Identification and Authentication Failures",
    "A08": "A08:2021-Software and Data Integrity Failures",
    "A09": "A09:2021-Security Logging and Monitoring Failures",
    "A10": "A10:2021-Server-Side Request Forgery (SSRF)",
}

UNMAPPED = "UNMAPPED"

# CWE -> OWASP Top 10:2021 mapping table (based on official OWASP CWE inclusions)
_CWE_TO_OWASP: Dict[str, str] = {
    # A01:2021 - Broken Access Control
    "CWE-22": "A01:2021-Broken Access Control",     # Path Traversal
    "CWE-23": "A01:2021-Broken Access Control",     # Relative Path Traversal
    "CWE-35": "A01:2021-Broken Access Control",     # Path Traversal: '.../...//'
    "CWE-59": "A01:2021-Broken Access Control",     # Link Resolution (Symlink)
    "CWE-200": "A01:2021-Broken Access Control",    # Exposure of Sensitive Information
    "CWE-219": "A01:2021-Broken Access Control",    # Storage under Web Root
    "CWE-264": "A01:2021-Broken Access Control",    # Permissions / Privileges
    "CWE-275": "A01:2021-Broken Access Control",    # Permission Issues
    "CWE-276": "A01:2021-Broken Access Control",    # Incorrect Default Permissions
    "CWE-284": "A01:2021-Broken Access Control",    # Improper Access Control
    "CWE-285": "A01:2021-Broken Access Control",    # Improper Authorization
    "CWE-352": "A01:2021-Broken Access Control",    # Cross-Site Request Forgery (CSRF)
    "CWE-359": "A01:2021-Broken Access Control",    # Exposure of Private Information
    "CWE-377": "A01:2021-Broken Access Control",    # Insecure Temporary File
    "CWE-402": "A01:2021-Broken Access Control",    # Transmission in Cleartext
    "CWE-425": "A01:2021-Broken Access Control",    # Direct Request ('Forced Browsing')
    "CWE-538": "A01:2021-Broken Access Control",    # Insertion of Sensitive Information
    "CWE-552": "A01:2021-Broken Access Control",    # Files accessible to External Entities
    "CWE-566": "A01:2021-Broken Access Control",    # Authorization Bypass Through User-Controlled SQL Primary Key
    "CWE-601": "A01:2021-Broken Access Control",    # Open Redirect
    "CWE-639": "A01:2021-Broken Access Control",    # Insecure Direct Object References (IDOR)
    "CWE-668": "A01:2021-Broken Access Control",    # Exposure to Wrong Sphere
    "CWE-862": "A01:2021-Broken Access Control",    # Missing Authorization
    "CWE-863": "A01:2021-Broken Access Control",    # Incorrect Authorization
    "CWE-922": "A01:2021-Broken Access Control",    # Insecure Storage of Sensitive Information

    # A02:2021 - Cryptographic Failures
    "CWE-259": "A02:2021-Cryptographic Failures",   # Hardcoded Password
    "CWE-261": "A02:2021-Cryptographic Failures",   # Weak Encoding
    "CWE-296": "A02:2021-Cryptographic Failures",   # Improper Certificate Validation
    "CWE-310": "A02:2021-Cryptographic Failures",   # Cryptographic Issues
    "CWE-319": "A02:2021-Cryptographic Failures",   # Cleartext Transmission of Sensitive Information
    "CWE-321": "A02:2021-Cryptographic Failures",   # Hard-coded Cryptographic Key
    "CWE-322": "A02:2021-Cryptographic Failures",   # Key Exchange without Entity Authentication
    "CWE-323": "A02:2021-Cryptographic Failures",   # Reusing a Nonce, Key Pair
    "CWE-324": "A02:2021-Cryptographic Failures",   # Use of a Key Past its Expiration Date
    "CWE-325": "A02:2021-Cryptographic Failures",   # Missing Cryptographic Step
    "CWE-326": "A02:2021-Cryptographic Failures",   # Inadequate Encryption Strength
    "CWE-327": "A02:2021-Cryptographic Failures",   # Use of Broken or Risky Cryptographic Algorithm
    "CWE-328": "A02:2021-Cryptographic Failures",   # Use of Weak Hash
    "CWE-329": "A02:2021-Cryptographic Failures",   # Generation of Predictable IV with CBC Mode
    "CWE-330": "A02:2021-Cryptographic Failures",   # Use of Insufficiently Random Values
    "CWE-331": "A02:2021-Cryptographic Failures",   # Insufficient Entropy
    "CWE-335": "A02:2021-Cryptographic Failures",   # Incorrect Usage of Seeds in PRNG
    "CWE-336": "A02:2021-Cryptographic Failures",   # Same Seed in PRNG
    "CWE-337": "A02:2021-Cryptographic Failures",   # Predictable Seed in PRNG
    "CWE-338": "A02:2021-Cryptographic Failures",   # Use of Cryptographically Weak PRNG
    "CWE-340": "A02:2021-Cryptographic Failures",   # Generation of Predictable Numbers
    "CWE-347": "A02:2021-Cryptographic Failures",   # Improper Verification of Cryptographic Signature
    "CWE-523": "A02:2021-Cryptographic Failures",   # Unprotected Transport of Credentials
    "CWE-757": "A02:2021-Cryptographic Failures",   # Selection of Less-Secure Algorithm During Negotiation
    "CWE-759": "A02:2021-Cryptographic Failures",   # Use of a One-Way Hash without a Salt
    "CWE-760": "A02:2021-Cryptographic Failures",   # Use of a One-Way Hash with a Predictable Salt
    "CWE-780": "A02:2021-Cryptographic Failures",   # Use of RSA Algorithm without OAEP
    "CWE-798": "A02:2021-Cryptographic Failures",   # Use of Hard-coded Credentials
    "CWE-916": "A02:2021-Cryptographic Failures",   # Use of Password Hash With Insufficient Computational Effort

    # A03:2021 - Injection
    "CWE-20": "A03:2021-Injection",                 # Improper Input Validation
    "CWE-74": "A03:2021-Injection",                 # Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')
    "CWE-75": "A03:2021-Injection",                 # Failure to Sanitize Special Elements
    "CWE-77": "A03:2021-Injection",                 # Command Injection
    "CWE-78": "A03:2021-Injection",                 # OS Command Injection
    "CWE-79": "A03:2021-Injection",                 # Cross-site Scripting (XSS)
    "CWE-80": "A03:2021-Injection",                 # Basic XSS
    "CWE-83": "A03:2021-Injection",                 # Improper Neutralization of Script in Attributes
    "CWE-87": "A03:2021-Injection",                 # Improper Neutralization of Alternate XSS Syntax
    "CWE-88": "A03:2021-Injection",                 # Argument Injection
    "CWE-89": "A03:2021-Injection",                 # SQL Injection
    "CWE-90": "A03:2021-Injection",                 # LDAP Injection
    "CWE-91": "A03:2021-Injection",                 # XML Injection
    "CWE-93": "A03:2021-Injection",                 # CRLF Injection
    "CWE-94": "A03:2021-Injection",                 # Code Injection
    "CWE-95": "A03:2021-Injection",                 # Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
    "CWE-96": "A03:2021-Injection",                 # Improper Neutralization of Directives in Statically Saved Code
    "CWE-99": "A03:2021-Injection",                 # Resource Injection
    "CWE-113": "A03:2021-Injection",                # HTTP Response Splitting
    "CWE-116": "A03:2021-Injection",                # Improper Encoding or Escaping of Output
    "CWE-138": "A03:2021-Injection",                # Improper Neutralization of Special Elements
    "CWE-184": "A03:2021-Injection",                # Incomplete List of Disallowed Inputs
    "CWE-470": "A03:2021-Injection",                # Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
    "CWE-564": "A03:2021-Injection",                # SQL Injection: Hibernate
    "CWE-610": "A03:2021-Injection",                # Externally Controlled Reference to a Resource in Another Sphere
    "CWE-643": "A03:2021-Injection",                # XPath Injection
    "CWE-644": "A03:2021-Injection",                # Improper Neutralization of HTTP Headers for Scripting
    "CWE-652": "A03:2021-Injection",                # Improper Neutralization of Data within XQuery Expressions
    "CWE-917": "A03:2021-Injection",                # Expression Language Injection

    # A04:2021 - Insecure Design
    "CWE-73": "A04:2021-Insecure Design",           # External Control of File Name or Path
    "CWE-183": "A04:2021-Insecure Design",          # Permissive List of Allowed Inputs
    "CWE-209": "A04:2021-Insecure Design",          # Information Exposure Through an Error Message
    "CWE-213": "A04:2021-Insecure Design",          # Exposure of Sensitive Information Due to Incompatible Policies
    "CWE-235": "A04:2021-Insecure Design",          # Improper Handling of Extra Parameters
    "CWE-256": "A04:2021-Insecure Design",          # Plaintext Storage of a Password
    "CWE-257": "A04:2021-Insecure Design",          # Storing Passwords in a Recoverable Format
    "CWE-266": "A04:2021-Insecure Design",          # Incorrect Privilege Assignment
    "CWE-269": "A04:2021-Insecure Design",          # Improper Privilege Management
    "CWE-280": "A04:2021-Insecure Design",          # Improper Handling of Insufficient Permissions or Privileges
    "CWE-311": "A04:2021-Insecure Design",          # Missing Encryption of Sensitive Data
    "CWE-312": "A04:2021-Insecure Design",          # Cleartext Storage of Sensitive Information
    "CWE-313": "A04:2021-Insecure Design",          # Cleartext Storage in a File or on Disk
    "CWE-316": "A04:2021-Insecure Design",          # Cleartext Storage of Sensitive Information in Memory
    "CWE-419": "A04:2021-Insecure Design",          # Unprotected Primary Channel
    "CWE-430": "A04:2021-Insecure Design",          # Deployment of Wrong Handler
    "CWE-434": "A04:2021-Insecure Design",          # Unrestricted Upload of File with Dangerous Type
    "CWE-444": "A04:2021-Insecure Design",          # Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')
    "CWE-451": "A04:2021-Insecure Design",          # User Interface Misrepresentation of Critical Information
    "CWE-501": "A04:2021-Insecure Design",          # Trust Boundary Violation
    "CWE-522": "A04:2021-Insecure Design",          # Insufficiently Protected Credentials
    "CWE-525": "A04:2021-Insecure Design",          # Use of Web Browser Cache Containing Sensitive Information
    "CWE-539": "A04:2021-Insecure Design",          # Use of Persistent Cookies Containing Sensitive Information
    "CWE-579": "A04:2021-Insecure Design",          # J2EE Bad Practices: Non-serializable Object Stored in Session
    "CWE-598": "A04:2021-Insecure Design",          # Use of GET Request Method With Sensitive Query Strings
    "CWE-602": "A04:2021-Insecure Design",          # Client-Side Enforcement of Server-Side Security
    "CWE-642": "A04:2021-Insecure Design",          # External Control of Critical State Data
    "CWE-646": "A04:2021-Insecure Design",          # Reliance on File Name or Extension of Externally-Supplied File
    "CWE-650": "A04:2021-Insecure Design",          # Trusting HTTP Permission Methods on the Server Side
    "CWE-653": "A04:2021-Insecure Design",          # Improper Support for Compartmentalization
    "CWE-656": "A04:2021-Insecure Design",          # Reliance on Security Through Obscurity
    "CWE-657": "A04:2021-Insecure Design",          # Violation of Secure Design Principles
    "CWE-799": "A04:2021-Insecure Design",          # Improper Control of Interaction Frequency
    "CWE-807": "A04:2021-Insecure Design",          # Reliance on Untrusted Inputs in a Security Decision
    "CWE-840": "A04:2021-Insecure Design",          # Business Logic Errors
    "CWE-841": "A04:2021-Insecure Design",          # Improper Enforcement of Behavioral Workflow
    "CWE-927": "A04:2021-Insecure Design",          # Use of Implicit Intent for Sensitive Communication
    "CWE-1021": "A04:2021-Insecure Design",         # Improper Restriction of Rendered UI Layers or Frames (Clickjacking)
    "CWE-1173": "A04:2021-Insecure Design",         # Improper Use of Validation Framework

    # A05:2021 - Security Misconfiguration
    "CWE-2": "A05:2021-Security Misconfiguration",   # Environment
    "CWE-11": "A05:2021-Security Misconfiguration",  # ASP.NET Misconfiguration: Creating Debug Binary
    "CWE-13": "A05:2021-Security Misconfiguration",  # ASP.NET Misconfiguration: Password in Configuration File
    "CWE-15": "A05:2021-Security Misconfiguration",  # External Control of System or Configuration Setting
    "CWE-16": "A05:2021-Security Misconfiguration",  # Configuration
    "CWE-260": "A05:2021-Security Misconfiguration", # Password in Configuration File
    "CWE-315": "A05:2021-Security Misconfiguration", # Cleartext Storage of Sensitive Information in a Cookie
    "CWE-520": "A05:2021-Security Misconfiguration", # .NET Misconfiguration: Use of Impersonation
    "CWE-526": "A05:2021-Security Misconfiguration", # Cleartext Storage of Sensitive Information in an Environment Variable
    "CWE-537": "A05:2021-Security Misconfiguration", # Java Runtime Error Message Containing Sensitive Information
    "CWE-541": "A05:2021-Security Misconfiguration", # Inclusion of Sensitive Information in an Include File
    "CWE-547": "A05:2021-Security Misconfiguration", # Use of Hard-coded, Security-relevant Constants
    "CWE-611": "A05:2021-Security Misconfiguration", # XML External Entity Reference (XXE)
    "CWE-614": "A05:2021-Security Misconfiguration", # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
    "CWE-756": "A05:2021-Security Misconfiguration", # Missing Custom Error Page
    "CWE-776": "A05:2021-Security Misconfiguration", # Improper Restriction of Recursive Entity References ('XML Entity Expansion')
    "CWE-942": "A05:2021-Security Misconfiguration", # Permissive Cross-domain Policy with Untrusted Domains (CORS)
    "CWE-1004": "A05:2021-Security Misconfiguration",# Sensitive Cookie Without 'HttpOnly' Flag
    "CWE-1032": "A05:2021-Security Misconfiguration",# Security Misconfiguration Architecture
    "CWE-1174": "A05:2021-Security Misconfiguration",# ASP.NET Misconfiguration: Improper Model Validation

    # A06:2021 - Vulnerable and Outdated Components
    "CWE-937": "A06:2021-Vulnerable and Outdated Components",   # Using Components with Known Vulnerabilities
    "CWE-1026": "A06:2021-Vulnerable and Outdated Components",  # Weaknesses in OSS
    "CWE-1035": "A06:2021-Vulnerable and Outdated Components",  # Vulnerable Third Party Component
    "CWE-1104": "A06:2021-Vulnerable and Outdated Components",  # Use of Unmaintained Third Party Components
    "CWE-1395": "A06:2021-Vulnerable and Outdated Components",  # Dependency on Vulnerable Third-Party Component

    # A07:2021 - Identification and Authentication Failures
    "CWE-255": "A07:2021-Identification and Authentication Failures", # Credentials Management
    "CWE-287": "A07:2021-Identification and Authentication Failures", # Improper Authentication
    "CWE-288": "A07:2021-Identification and Authentication Failures", # Authentication Bypass Using an Alternate Path or Channel
    "CWE-290": "A07:2021-Identification and Authentication Failures", # Authentication Bypass by Spoofing
    "CWE-294": "A07:2021-Identification and Authentication Failures", # Authentication Bypass by Capture-replay
    "CWE-295": "A07:2021-Identification and Authentication Failures", # Improper Certificate Validation
    "CWE-297": "A07:2021-Identification and Authentication Failures", # Improper Validation of Certificate with Host Mismatch
    "CWE-300": "A07:2021-Identification and Authentication Failures", # Channel Accessible by Non-Endpoint
    "CWE-302": "A07:2021-Identification and Authentication Failures", # Authentication Bypass by Assumed-Immutable Data
    "CWE-304": "A07:2021-Identification and Authentication Failures", # Missing Critical Step in Authentication
    "CWE-306": "A07:2021-Identification and Authentication Failures", # Missing Authentication for Critical Function
    "CWE-307": "A07:2021-Identification and Authentication Failures", # Improper Restriction of Excessive Authentication Attempts
    "CWE-346": "A07:2021-Identification and Authentication Failures", # Origin Validation Error
    "CWE-384": "A07:2021-Identification and Authentication Failures", # Session Fixation
    "CWE-521": "A07:2021-Identification and Authentication Failures", # Weak Password Requirements
    "CWE-613": "A07:2021-Identification and Authentication Failures", # Insufficient Session Expiration
    "CWE-620": "A07:2021-Identification and Authentication Failures", # Unverified Password Change
    "CWE-640": "A07:2021-Identification and Authentication Failures", # Weak Password Recovery Mechanism
    "CWE-804": "A07:2021-Identification and Authentication Failures", # Guessable CAPTCHA
    "CWE-842": "A07:2021-Identification and Authentication Failures", # Placement of User into Wrong Session
    "CWE-911": "A07:2021-Identification and Authentication Failures", # Improper Update of Alternate Key
    "CWE-1188": "A07:2021-Identification and Authentication Failures",# Insecure Default Initialization of Resource
    "CWE-1216": "A07:2021-Identification and Authentication Failures",# Lockout Mechanism Failure

    # A08:2021 - Software and Data Integrity Failures
    "CWE-345": "A08:2021-Software and Data Integrity Failures", # Insufficient Verification of Data Authenticity
    "CWE-353": "A08:2021-Software and Data Integrity Failures", # Missing Support for Integrity Check
    "CWE-426": "A08:2021-Software and Data Integrity Failures", # Untrusted Search Path
    "CWE-494": "A08:2021-Software and Data Integrity Failures", # Download of Code Without Integrity Check
    "CWE-502": "A08:2021-Software and Data Integrity Failures", # Deserialization of Untrusted Data
    "CWE-565": "A08:2021-Software and Data Integrity Failures", # Reliance on Cookies without Validation and Integrity Checking
    "CWE-784": "A08:2021-Software and Data Integrity Failures", # Reliance on Cookies without Validation and Integrity Checking in a Security Decision
    "CWE-829": "A08:2021-Software and Data Integrity Failures", # Inclusion of Functionality from Untrusted Control Sphere
    "CWE-830": "A08:2021-Software and Data Integrity Failures", # Inclusion of Web Functionality from Untrusted Source
    "CWE-915": "A08:2021-Software and Data Integrity Failures", # Improperly Controlled Modification of Dynamically-Determined Object Attributes

    # A09:2021 - Security Logging and Monitoring Failures
    "CWE-117": "A09:2021-Security Logging and Monitoring Failures", # Improper Output Handling for Logs
    "CWE-223": "A09:2021-Security Logging and Monitoring Failures", # Omission of Information from Log
    "CWE-532": "A09:2021-Security Logging and Monitoring Failures", # Insertion of Sensitive Information into Log File
    "CWE-778": "A09:2021-Security Logging and Monitoring Failures", # Insufficient Logging

    # A10:2021 - Server-Side Request Forgery (SSRF)
    "CWE-918": "A10:2021-Server-Side Request Forgery (SSRF)",       # Server-Side Request Forgery (SSRF)
}


def normalize_cwe_id(cwe_input: Optional[str]) -> str:
    """Normalize a CWE representation to canonical uppercase format 'CWE-XXX'."""
    if not cwe_input:
        return "CWE-UNKNOWN"
    val = str(cwe_input).strip().upper()
    if val.startswith("CWE_"):
        val = "CWE-" + val[4:]
    elif val.isdigit():
        val = f"CWE-{val}"
    elif not val.startswith("CWE-"):
        # e.g. "CWE89" -> "CWE-89"
        if val.startswith("CWE"):
            suffix = val[3:].lstrip("-_")
            val = f"CWE-{suffix}"
    return val


def map_cwe_to_owasp(cwe: Optional[str]) -> str:
    """Map a CWE identifier to its official OWASP Top 10:2021 category.

    If the CWE is not part of the official OWASP Top 10:2021 mapping,
    returns 'UNMAPPED'.
    """
    normalized = normalize_cwe_id(cwe)
    return _CWE_TO_OWASP.get(normalized, UNMAPPED)


def get_owasp_mapping_table() -> Dict[str, Any]:
    """Return the complete CWE -> OWASP Top 10 mapping table with metadata."""
    return {
        "standard": "OWASP Top 10:2021",
        "total_mapped_cwes": len(_CWE_TO_OWASP),
        "categories": OWASP_TOP10_2021,
        "mapping": dict(sorted(_CWE_TO_OWASP.items())),
        "unmapped_designation": UNMAPPED,
        "distinction_note": (
            "OWASP Top 10 is an awareness document ranking the top 10 web application "
            "security risks by prevalence and consensus. The OWASP Benchmark Project is a "
            "standardized test suite (e.g. 2,740 test cases) measuring SAST tool precision "
            "and recall. They are distinct concepts and should not be conflated."
        ),
    }


def map_findings_to_owasp(findings: List[Any]) -> List[Dict[str, Any]]:
    """Map a list of finding objects/dicts to their OWASP Top 10 category."""
    mapped = []
    for f in findings:
        cwe = getattr(f, "cwe", None) if hasattr(f, "cwe") else (f.get("cwe") if isinstance(f, dict) else None)
        f_id = getattr(f, "finding_id", None) if hasattr(f, "finding_id") else (f.get("finding_id") if isinstance(f, dict) else None)
        owasp_cat = map_cwe_to_owasp(cwe)
        mapped.append({
            "finding_id": f_id,
            "cwe": normalize_cwe_id(cwe),
            "owasp_top10": owasp_cat,
            "is_mapped": owasp_cat != UNMAPPED,
        })
    return mapped
