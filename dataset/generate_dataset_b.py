#!/usr/bin/env python3
"""
Dataset B Generator for HalluciShield
=====================================
Generates 500 internally constructed AI-generated code samples (387 positive, 113 negative)
for evaluating HalluciShield AI security analysis.

Uses Groq LLM (qwen/qwen3.8-27b) for generation.
"""

import os
import json
import hashlib
import random
import time
import csv
import signal
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field

# Load environment
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

# Groq API configuration
GROQ_API_KEY = os.getenv("LLM_API_KEY", "")
GROQ_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1")
# Working model verified via Groq Models API: qwen/qwen3.8-27b (active, supports chat/completions, json_mode, tools, reasoning)
GROQ_MODEL = os.getenv("DEFAULT_LLM_MODEL", "qwen/qwen3.8-27b")

# Global flag for graceful shutdown
_shutdown_requested = False

def _signal_handler(signum, frame):
    """Signal handler for graceful shutdown on Ctrl+C."""
    global _shutdown_requested
    print("\n[Shutdown] Ctrl+C received. Finishing current sample and saving...")
    _shutdown_requested = True

# Register signal handlers
signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

# Dataset configuration
DATASET_VERSION = "v1.0"
TOTAL_SAMPLES = 500
POSITIVE_COUNT = 387
NEGATIVE_COUNT = 113

# Category distribution for positive samples
# Deterministic distribution based on research design
POSITIVE_CATEGORIES = {
    "cwe89": {"name": "SQL Injection", "cwe": "CWE-89", "count": 55},
    "cwe79": {"name": "Cross-Site Scripting (XSS)", "cwe": "CWE-79", "count": 55},
    "cwe798": {"name": "Hardcoded Credentials", "cwe": "CWE-798", "count": 55},
    "cwe78": {"name": "OS Command Injection", "cwe": "CWE-78", "count": 55},
    "cwe22": {"name": "Path Traversal", "cwe": "CWE-22", "count": 55},
    "cwe347": {"name": "Improper JWT Verification", "cwe": "CWE-347", "count": 45},
    "cwe256": {"name": "Authentication Flaws", "cwe": "CWE-256/330/328/287/330", "count": 30},
    "hallucinated_api": {"name": "Hallucinated API", "cwe": "CWE-706", "count": 23},
    "hallucinated_pkg": {"name": "Hallucinated Package", "cwe": "CWE-1395", "count": 14},
}

# Verify total
assert sum(c["count"] for c in POSITIVE_CATEGORIES.values()) == POSITIVE_COUNT

# Generation parameters
GENERATION_CONFIG = {
    "model": "openai/gpt-oss-20b",
    "temperature_pos": 0.2,
    "temperature_neg": 0.1,
    "top_p": 0.95,
    "max_tokens_pos": 1024,
    "max_tokens_neg": 512,
    "prompt_version": "v1.0",
    "dataset_version": DATASET_VERSION,
    "generator_provider": "groq",
    "generator_model": "openai/gpt-oss-20b",
    "generation_method": "llm_generation",
    "random_seed": 42,
}

# Languages supported by HalluciShield
SUPPORTED_LANGUAGES = ["python", "javascript", "typescript", "java", "go"]

# API rate limiting
API_CALL_DELAY = 0.5  # seconds between calls


@dataclass
class SampleMetadata:
    """Metadata for a single dataset sample."""
    sample_id: str
    language: str
    cwe: str
    category: str
    label: str  # "positive" or "negative"
    generator_model: str
    generation_prompt: str
    ground_truth: str
    file_path: str
    sha256: str
    generator_provider: str = field(default="groq")
    temperature: float = field(default=0.7)
    top_p: float = field(default=0.95)
    max_tokens: int = field(default=2048)
    prompt_version: str = field(default="v1.0")
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    generation_method: str = field(default="llm_generation")
    dataset_version: str = field(default="v1.0")
    vulnerability_type: str = field(default="")
    severity: str = field(default="")
    description: str = field(default="")
    expected_detection: bool = field(default=True)
    expected_patch_types: List[str] = field(default_factory=list)


def compute_sha256(content: str) -> str:
    """Compute SHA-256 hash of content."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def _load_existing_metadata(csv_path: Path) -> List[SampleMetadata]:
    """Load existing metadata from CSV for resume capability."""
    if not csv_path.exists():
        return []
    samples = []
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Convert string fields back to proper types
                row['temperature'] = float(row['temperature'])
                row['top_p'] = float(row['top_p'])
                row['max_tokens'] = int(row['max_tokens'])
                row['expected_detection'] = row['expected_detection'].lower() == 'true'
                try:
                    row['expected_patch_types'] = json.loads(row['expected_patch_types'])
                except:
                    row['expected_patch_types'] = []
                samples.append(SampleMetadata(**row))
    except Exception as e:
        print(f"[Resume] Warning: Could not load existing metadata: {e}")
        return []
    return samples


def _get_existing_hashes_and_ids(samples: List[SampleMetadata]) -> tuple:
    """Get existing hashes and IDs for duplicate detection."""
    hashes = set()
    ids = set()
    for s in samples:
        hashes.add(s.sha256)
        ids.add(s.sample_id)
    return hashes, ids


def _append_metadata_atomic(samples: List[SampleMetadata], csv_path: Path, json_path: Path):
    """Append metadata to CSV and rewrite JSON atomically."""
    fieldnames = [
        "sample_id", "language", "cwe", "category", "label",
        "generator_model", "generation_prompt", "ground_truth",
        "file_path", "sha256", "generator_provider", "temperature",
        "top_p", "max_tokens", "prompt_version", "timestamp",
        "generation_method", "dataset_version", "vulnerability_type",
        "severity", "description", "expected_detection",
        "expected_patch_types"
    ]
    
    # Write CSV atomically using temp file
    temp_csv = csv_path.with_suffix('.tmp')
    with open(temp_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for sample in samples:
            row = asdict(sample)
            row['expected_patch_types'] = json.dumps(sample.expected_patch_types)
            writer.writerow(row)
    temp_csv.replace(csv_path)
    
    # Write JSON atomically using temp file
    temp_json = json_path.with_suffix('.tmp')
    with open(temp_json, 'w', encoding='utf-8') as f:
        json.dump([asdict(s) for s in samples], f, indent=2, default=str)
    temp_json.replace(json_path)


def _append_single_metadata(sample: SampleMetadata, csv_path: Path, json_path: Path, existing_samples: List[SampleMetadata]):
    """Append a single sample's metadata to both CSV and JSON files."""
    existing_samples.append(sample)
    _append_metadata_atomic(existing_samples, csv_path, json_path)


def call_groq_llm(prompt: str, temperature: float = 0.2, max_tokens: int = 1024) -> str:
    """Call Groq LLM API with exponential backoff retry logic."""
    import httpx
    
    if not GROQ_API_KEY:
        return ""
    
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    
    url = f"{GROQ_BASE_URL.rstrip('/')}/chat/completions"
    payload = {
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "response_format": {"type": "json_object"},
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    
    # Exponential backoff configuration
    max_retries = 5
    base_delay = 2.0  # seconds
    max_delay = 60.0  # seconds
    
    for attempt in range(max_retries):
        try:
            with httpx.Client(timeout=90.0) as client:
                resp = client.post(url, json=payload, headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"})
                
                if resp.status_code == 200:
                    data = resp.json()
                    content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                    return content if isinstance(content, str) else ""
                
                elif resp.status_code == 429:
                    # Rate limited - extract retry-after if available, otherwise use exponential backoff
                    retry_after = resp.headers.get("retry-after")
                    if retry_after:
                        try:
                            delay = min(float(retry_after), max_delay)
                        except ValueError:
                            delay = min(base_delay * (2 ** attempt), max_delay)
                    else:
                        delay = min(base_delay * (2 ** attempt), max_delay)
                    
                    # Add jitter
                    delay += random.uniform(0, 1.0)
                    
                    print(f"Rate limited (attempt {attempt + 1}/{max_retries}). Waiting {delay:.1f}s...")
                    time.sleep(delay)
                    continue
                
                elif resp.status_code == 503:
                    # Service unavailable - transient error, retry with exponential backoff + jitter
                    # Respect Retry-After if provided, otherwise use exponential backoff
                    retry_after = resp.headers.get("retry-after")
                    if retry_after:
                        try:
                            delay = min(float(retry_after), max_delay)
                        except ValueError:
                            delay = min(base_delay * (2 ** attempt), max_delay)
                    else:
                        delay = min(base_delay * (2 ** attempt), max_delay)
                    
                    # Add jitter
                    delay += random.uniform(0, 1.0)
                    
                    print(f"Service unavailable 503 (attempt {attempt + 1}/{max_retries}). Waiting {delay:.1f}s...")
                    time.sleep(delay)
                    continue
                
                elif resp.status_code == 400:
                    # Check if it's a JSON validation error (not retryable)
                    if "json_validate_failed" in resp.text:
                        print(f"JSON validation failed: {resp.text[:200]}")
                        return ""
                    print(f"API error: {resp.status_code} - {resp.text[:200]}")
                    return ""
                
                else:
                    print(f"API error: {resp.status_code} - {resp.text[:200]}")
                    # For other errors, retry with backoff
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    delay += random.uniform(0, 1.0)
                    print(f"Retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries})...")
                    time.sleep(delay)
                    continue
                    
        except httpx.TimeoutException:
            print(f"Timeout (attempt {attempt + 1}/{max_retries}). Retrying...")
            delay = min(base_delay * (2 ** attempt), max_delay)
            delay += random.uniform(0, 1.0)
            time.sleep(delay)
            continue
        except Exception as e:
            print(f"LLM call failed: {e}")
            if attempt == max_retries - 1:
                return ""
            delay = min(base_delay * (2 ** attempt), max_delay)
            delay += random.uniform(0, 1.0)
            time.sleep(delay)
            continue
    
    print(f"Max retries ({max_retries}) exceeded. Giving up.")
    return ""


def generate_sql_injection_sample(language: str, seed: int) -> Dict[str, Any]:
    """Generate SQL injection vulnerable code sample."""
    templates = {
        "python": [
            "cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)",
            "cursor.execute(f\"SELECT * FROM orders WHERE order_id = {order_id}\")",
            "query = \"SELECT * FROM products WHERE name LIKE '%\" + search_term + \"%'\"; cursor.execute(query)",
            "cursor.execute(\"UPDATE users SET role='\" + new_role + \"' WHERE id=\" + uid)",
            "cursor.execute('INSERT INTO logs(msg) VALUES(' + msg + ')')",
        ],
        "javascript": [
            "db.query('SELECT * FROM users WHERE id = ' + userId)",
            "const query = `SELECT * FROM orders WHERE order_id = ${orderId}`; db.query(query)",
            "const sql = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`; db.query(sql)",
            "db.query('UPDATE users SET role=' + newRole + ' WHERE id=' + uid)",
            "db.query('INSERT INTO logs(msg) VALUES(' + msg + ')')",
        ],
    }
    
    base = random.choice(templates.get(language, templates["python"]))
    
    prompt = f"""Generate {language} code with SQL injection (CWE-89). Return JSON only: {{"code":"...","line":<int>,"desc":"...","sev":"HIGH|CRITICAL","type":"SQL_INJECTION","cwe":"CWE-89"}}. Code must be realistic app code with string-concat SQL. No extra text."""
    
    response = call_groq_llm(prompt, temperature=0.2, max_tokens=1024)
    if response:
        try:
            result = json.loads(response)
            code = result.get("code", base)
            vulnerable_line = result.get("line", 1)
            description = result.get("desc", "SQL injection via string concatenation")
            severity = result.get("sev", "CRITICAL")
        except:
            code = base
            vulnerable_line = 1
            description = "SQL injection via string concatenation"
            severity = "CRITICAL"
    else:
        code = base
        vulnerable_line = 1
        description = "SQL injection via string concatenation"
        severity = "CRITICAL"
    
    return {
        "code": code,
        "vulnerable_line": vulnerable_line,
        "description": description,
        "severity": severity,
        "vulnerability_type": "SQL_INJECTION",
        "cwe": "CWE-89",
    }


def generate_xss_sample(language: str, seed: int) -> Dict[str, Any]:
    """Generate XSS vulnerable code sample."""
    prompt = f"""Generate {language} code with XSS (CWE-79). Return JSON only: {{"code":"...","line":<int>,"desc":"...","sev":"MEDIUM|HIGH|CRITICAL","type":"CROSS_SITE_SCRIPTING","cwe":"CWE-79"}}. Code must have unescaped user input in HTML/JS output. No extra text."""
    
    response = call_groq_llm(prompt, temperature=0.2, max_tokens=1024)
    if response:
        try:
            result = json.loads(response)
            code = result.get("code", 'return f"<h1>Welcome {username}</h1>"')
            vulnerable_line = result.get("line", 1)
            description = result.get("desc", "Unescaped user input in HTML response")
            severity = result.get("sev", "HIGH")
        except:
            code = 'return f"<h1>Welcome {username}</h1>"'
            vulnerable_line = 1
            description = "Unescaped user input in HTML response"
            severity = "HIGH"
    else:
        code = 'return f"<h1>Welcome {username}</h1>"'
        vulnerable_line = 1
        description = "Unescaped user input in HTML response"
        severity = "HIGH"
    
    return {
        "code": code,
        "vulnerable_line": vulnerable_line,
        "description": description,
        "severity": severity,
        "vulnerability_type": "CROSS_SITE_SCRIPTING",
        "cwe": "CWE-79",
    }


def generate_command_injection_sample(language: str, seed: int) -> Dict[str, Any]:
    """Generate command injection vulnerable code sample."""
    prompt = f"""Generate {language} code with OS command injection (CWE-78). Return JSON only: {{"code":"...","line":<int>,"desc":"...","sev":"HIGH|CRITICAL","type":"COMMAND_INJECTION","cwe":"CWE-78"}}. Code must use user input directly in os.system/subprocess. No extra text."""
    
    response = call_groq_llm(prompt, temperature=0.2, max_tokens=1024)
    if response:
        try:
            result = json.loads(response)
            code = result.get("code", 'os.system("ping -c 4 " + host)')
            vulnerable_line = result.get("line", 1)
            description = result.get("desc", "Direct OS command with user input")
            severity = result.get("sev", "CRITICAL")
        except:
            code = 'os.system("ping -c 4 " + host)'
            vulnerable_line = 1
            description = "Direct OS command with user input"
            severity = "CRITICAL"
    else:
        code = 'os.system("ping -c 4 " + host)'
        vulnerable_line = 1
        description = "Direct OS command with user input"
        severity = "CRITICAL"
    
    return {
        "code": code,
        "vulnerable_line": vulnerable_line,
        "description": description,
        "severity": severity,
        "vulnerability_type": "COMMAND_INJECTION",
        "cwe": "CWE-78",
    }


def generate_path_traversal_sample(language: str, seed: int) -> Dict[str, Any]:
    """Generate path traversal vulnerable code sample."""
    prompt = f"""Generate {language} code with path traversal (CWE-22). Return JSON only: {{"code":"...","line":<int>,"desc":"...","sev":"MEDIUM|HIGH","type":"PATH_TRAVERSAL","cwe":"CWE-22"}}. Code must use unsanitized user input in file paths. No extra text."""
    
    response = call_groq_llm(prompt, temperature=0.2, max_tokens=1024)
    if response:
        try:
            result = json.loads(response)
            code = result.get("code", 'open(os.path.join("/data/files", user_filename)).read()')
            vulnerable_line = result.get("line", 1)
            description = result.get("desc", "Unsanitized filename in path join")
            severity = result.get("sev", "HIGH")
        except:
            code = 'open(os.path.join("/data/files", user_filename)).read()'
            vulnerable_line = 1
            description = "Unsanitized filename in path join"
            severity = "HIGH"
    else:
        code = 'open(os.path.join("/data/files", user_filename)).read()'
        vulnerable_line = 1
        description = "Unsanitized filename in path join"
        severity = "HIGH"
    
    return {
        "code": code,
        "vulnerable_line": vulnerable_line,
        "description": description,
        "severity": severity,
        "vulnerability_type": "PATH_TRAVERSAL",
        "cwe": "CWE-22",
    }


def generate_hardcoded_secrets_sample(language: str, seed: int) -> Dict[str, Any]:
    """Generate hardcoded secrets vulnerable code sample."""
    prompt = f"""Generate {language} code with hardcoded secrets (CWE-798). Return JSON only: {{"code":"...","line":<int>,"desc":"...","sev":"HIGH|CRITICAL","type":"HARDCODED_SECRET","cwe":"CWE-798"}}. Code must have hardcoded passwords/API keys/secrets. No extra text."""
    
    response = call_groq_llm(prompt, temperature=0.2, max_tokens=1024)
    if response:
        try:
            result = json.loads(response)
            code = result.get("code", 'DB_PASSWORD = "super_secret_123!"')
            vulnerable_line = result.get("line", 1)
            description = result.get("desc", "Hardcoded database password")
            severity = result.get("sev", "CRITICAL")
        except:
            code = 'DB_PASSWORD = "super_secret_123!"'
            vulnerable_line = 1
            description = "Hardcoded database password"
            severity = "CRITICAL"
    else:
        code = 'DB_PASSWORD = "super_secret_123!"'
        vulnerable_line = 1
        description = "Hardcoded database password"
        severity = "CRITICAL"
    
    return {
        "code": code,
        "vulnerable_line": vulnerable_line,
        "description": description,
        "severity": severity,
        "vulnerability_type": "HARDCODED_SECRET",
        "cwe": "CWE-798",
    }


def generate_jwt_issue_sample(language: str, seed: int) -> Dict[str, Any]:
    """Generate JWT vulnerability sample."""
    prompt = f"""Generate {language} code with JWT flaw (CWE-347). Return JSON only: {{"code":"...","line":<int>,"desc":"...","sev":"HIGH|CRITICAL","type":"INSECURE_JWT","cwe":"CWE-347"}}. Code must have JWT flaws (disabled verify, weak secret, alg:none, no exp). No extra text."""
    
    response = call_groq_llm(prompt, temperature=0.2, max_tokens=1024)
    if response:
        try:
            result = json.loads(response)
            code = result.get("code", 'payload = jwt.decode(token, options={"verify_signature": False})')
            vulnerable_line = result.get("line", 1)
            description = result.get("desc", "JWT signature verification disabled")
            severity = result.get("sev", "CRITICAL")
        except:
            code = 'payload = jwt.decode(token, options={"verify_signature": False})'
            vulnerable_line = 1
            description = "JWT signature verification disabled"
            severity = "CRITICAL"
    else:
        code = 'payload = jwt.decode(token, options={"verify_signature": False})'
        vulnerable_line = 1
        description = "JWT signature verification disabled"
        severity = "CRITICAL"
    
    return {
        "code": code,
        "vulnerable_line": vulnerable_line,
        "description": description,
        "severity": severity,
        "vulnerability_type": "INSECURE_JWT",
        "cwe": "CWE-347",
    }


def generate_auth_flaw_sample(language: str, seed: int) -> Dict[str, Any]:
    """Generate authentication flaw sample."""
    prompt = f"""Generate {language} code with auth flaw (CWE-256/330/328/287/330). Return JSON only: {{"code":"...","line":<int>,"desc":"...","sev":"HIGH|CRITICAL","type":"AUTH_FLAW","cwe":"CWE-256"}}. Code must have auth flaw (plaintext pwd, predictable token, weak hash, client-controlled admin, non-crypto OTP). No extra text."""
    
    response = call_groq_llm(prompt, temperature=0.2, max_tokens=1024)
    if response:
        try:
            result = json.loads(response)
            code = result.get("code", 'if password == stored_password: login(user)')
            vulnerable_line = result.get("line", 1)
            description = result.get("desc", "Plaintext password comparison")
            severity = result.get("sev", "HIGH")
        except:
            code = 'if password == stored_password: login(user)'
            vulnerable_line = 1
            description = "Plaintext password comparison"
            severity = "HIGH"
    else:
        code = 'if password == stored_password: login(user)'
        vulnerable_line = 1
        description = "Plaintext password comparison"
        severity = "HIGH"
    
    return {
        "code": code,
        "vulnerable_line": vulnerable_line,
        "description": description,
        "severity": severity,
        "vulnerability_type": "AUTH_FLAW",
        "cwe": "CWE-256",
    }


def generate_hallucinated_api_sample(language: str, seed: int) -> Dict[str, Any]:
    """Generate hallucinated API sample."""
    prompt = f"""Generate {language} code with hallucinated API (CWE-706). Return JSON only: {{"code":"...","line":<int>,"desc":"...","sev":"MEDIUM|HIGH","type":"HALLUCINATED_API","cwe":"CWE-706"}}. Code must use non-existent API (e.g., stripe.Charges.create, sendgrid.client.send, requests_oauth2.Client). No extra text."""
    
    response = call_groq_llm(prompt, temperature=0.2, max_tokens=1024)
    if response:
        try:
            result = json.loads(response)
            code = result.get("code", "stripe.api_key = 'sk_live_fake_key'\nstripe.Charges.create(amount=100)")
            vulnerable_line = result.get("line", 1)
            description = result.get("desc", "Hallucinated Stripe Charges API (should be PaymentIntents)")
            severity = result.get("sev", "HIGH")
        except:
            code = "stripe.api_key = 'sk_live_fake_key'\nstripe.Charges.create(amount=100)"
            vulnerable_line = 1
            description = "Hallucinated Stripe Charges API (should be PaymentIntents)"
            severity = "HIGH"
    else:
        code = "stripe.api_key = 'sk_live_fake_key'\nstripe.Charges.create(amount=100)"
        vulnerable_line = 1
        description = "Hallucinated Stripe Charges API (should be PaymentIntents)"
        severity = "HIGH"
    
    return {
        "code": code,
        "vulnerable_line": vulnerable_line,
        "description": description,
        "severity": severity,
        "vulnerability_type": "HALLUCINATED_API",
        "cwe": "CWE-706",
    }


def generate_hallucinated_pkg_sample(language: str, seed: int) -> Dict[str, Any]:
    """Generate hallucinated package sample."""
    prompt = f"""Generate a realistic {language} code snippet importing a hallucinated/non-existent package (CWE-1395).
The code should import a package that doesn't exist on PyPI/npm/maven (e.g., cryptolib, hashlib_utils, validlib, aes_crypto, uuid_utils).
Include the vulnerable line.

Return JSON with:
- "code": the vulnerable code snippet
- "vulnerable_line": line number of vulnerability
- "description": brief description of the hallucinated package
- "severity": "HIGH" or "MEDIUM"
- "vulnerability_type": "HALLUCINATED_PACKAGE"
- "cwe": "CWE-1395"
"""
    
    response = call_groq_llm(prompt, temperature=0.7, max_tokens=2048)
    if response:
        try:
            result = json.loads(response)
            code = result.get("code", 'from cryptolib import encrypt; encrypted = encrypt(data, key)')
            vulnerable_line = result.get("vulnerable_line", 1)
            description = result.get("description", "Non-existent cryptolib package")
            severity = result.get("severity", "HIGH")
        except:
            code = 'from cryptolib import encrypt; encrypted = encrypt(data, key)'
            vulnerable_line = 1
            description = "Non-existent cryptolib package"
            severity = "HIGH"
    else:
        code = 'from cryptolib import encrypt; encrypted = encrypt(data, key)'
        vulnerable_line = 1
        description = "Non-existent cryptolib package"
        severity = "HIGH"
    
    return {
        "code": code,
        "vulnerable_line": vulnerable_line,
        "description": description,
        "severity": severity,
        "vulnerability_type": "HALLUCINATED_PACKAGE",
        "cwe": "CWE-1395",
    }


def generate_clean_sample(language: str, seed: int) -> Dict[str, Any]:
    """Generate clean (negative) code sample with no intentional vulnerabilities."""
    prompt = f"""Generate {language} clean code (no vulnerabilities). Return ONLY this JSON format exactly:
{{"code": "def get_user(username):\\n    cursor.execute(\\"SELECT * FROM users WHERE username = ?\\", (username,))\\n    return cursor.fetchone()", "desc": "Safe parameterized query for user lookup"}}

Code must follow security best practices: parameterized SQL, escaped output, safe subprocess, pathlib paths, env vars for secrets, proper JWT verify, real APIs/packages. No extra text."""
    
    response = call_groq_llm(prompt, temperature=0.1, max_tokens=512)
    if response:
        try:
            result = json.loads(response)
            code = result.get("code", 'def get_user(username):\n    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))\n    return cursor.fetchone()')
            description = result.get("desc", "Safe parameterized query for user lookup")
        except:
            code = 'def get_user(username):\n    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))\n    return cursor.fetchone()'
            description = "Safe parameterized query for user lookup"
    else:
        code = 'def get_user(username):\n    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))\n    return cursor.fetchone()'
        description = "Safe parameterized query for user lookup"
    
    return {
        "code": code,
        "description": description,
    }


# Category generator mapping
CATEGORY_GENERATORS = {
    "cwe89": generate_sql_injection_sample,
    "cwe79": generate_xss_sample,
    "cwe78": generate_command_injection_sample,
    "cwe22": generate_path_traversal_sample,
    "cwe798": generate_hardcoded_secrets_sample,
    "cwe347": generate_jwt_issue_sample,
    "cwe256": generate_auth_flaw_sample,
    "hallucinated_api": generate_hallucinated_api_sample,
    "hallucinated_pkg": generate_hallucinated_pkg_sample,
}

NEGATIVE_GENERATOR = generate_clean_sample


def generate_positive_samples(dataset_dir: Path, csv_path: Path, json_path: Path) -> List[SampleMetadata]:
    """Generate all positive samples with per-sample persistence and resume capability."""
    # Load existing metadata for resume
    existing_samples = _load_existing_metadata(csv_path)
    existing_hashes, existing_ids = _get_existing_hashes_and_ids(existing_samples)
    
    samples = list(existing_samples)
    sample_index = len(existing_samples)
    
    # Count how many positive samples we already have per category
    existing_cat_counts = {}
    for s in existing_samples:
        if s.label == "positive":
            existing_cat_counts[s.category] = existing_cat_counts.get(s.category, 0) + 1
    
    dataset_root = Path("dataset/dataset-b")
    
    for cat_key, cat_info in POSITIVE_CATEGORIES.items():
        generator = CATEGORY_GENERATORS[cat_key]
        count = cat_info["count"]
        cwe = cat_info["cwe"]
        category_name = cat_key
        
        # Check how many we already have for this category
        already_done = existing_cat_counts.get(cat_key, 0)
        remaining = count - already_done
        if remaining <= 0:
            print(f"  {cat_key}: Already complete ({already_done}/{count})")
            continue
        
        for i in range(remaining):
            global _shutdown_requested
            if _shutdown_requested:
                print("[Shutdown] Requested. Stopping generation.")
                return samples
            
            sample_index += 1
            language = random.choice(SUPPORTED_LANGUAGES)
            seed = random.randint(0, 2**32 - 1)
            
            # Generate the sample
            result = generator(language, seed)
            
            # Create file path
            ext_map = {"python": "py", "javascript": "js", "typescript": "ts", "java": "java", "go": "go"}
            ext = ext_map.get(language, "py")
            file_name = f"{cat_key}_{i+already_done+1:03d}.{ext}"
            file_path = f"positive/{cat_key}/{file_name}"
            full_path = dataset_root / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write source file atomically
            temp_file = full_path.with_suffix('.tmp')
            temp_file.write_text(result["code"])
            temp_file.replace(full_path)
            
            # Compute hash
            sha256 = compute_sha256(result["code"])
            
            # Check for duplicate hash
            if sha256 in existing_hashes:
                print(f"  Duplicate hash detected, skipping sample")
                continue
            existing_hashes.add(sha256)
            
            # Create metadata
            sample_index += 1
            sample_id = f"DS-B-{sample_index:04d}"
            metadata = SampleMetadata(
                sample_id=sample_id,
                language=language,
                cwe=result["cwe"],
                category=category_name,
                label="positive",
                generator_model=GROQ_MODEL,
                generation_prompt=f"Generate {cat_info['name']} ({cwe}) vulnerable {language} code",
                ground_truth=f"Intentional {result['vulnerability_type']} vulnerability ({cwe}) at line {result['vulnerable_line']}: {result['description']}",
                file_path=file_path,
                sha256=sha256,
                vulnerability_type=result["vulnerability_type"],
                severity=result["severity"],
                description=result["description"],
                temperature=0.2,
                max_tokens=1024,
            )
            
            # Persist metadata immediately
            existing_samples.append(metadata)
            _append_metadata_atomic(existing_samples, Path("dataset/dataset-b/metadata.csv"), Path("dataset/dataset-b/metadata.json"))
            
            time.sleep(API_CALL_DELAY)
            
            if _shutdown_requested:
                print("[Shutdown] Requested. Stopping generation.")
                return existing_samples
    
    return existing_samples


def generate_negative_samples(dataset_dir: Path, csv_path: Path, json_path: Path) -> List[SampleMetadata]:
    """Generate all negative (clean) samples with per-sample persistence and resume capability."""
    # Load existing metadata for resume
    existing_samples = _load_existing_metadata(csv_path)
    existing_hashes, existing_ids = _get_existing_hashes_and_ids(existing_samples)
    
    samples = list(existing_samples)
    
    # Count how many negative samples we already have
    existing_neg = sum(1 for s in existing_samples if s.label == "negative")
    remaining = NEGATIVE_COUNT - len([s for s in existing_samples if s.label == "negative"])
    if remaining <= 0:
        print(f"  Negative samples: Already complete ({existing_neg}/{NEGATIVE_COUNT})")
        return existing_samples
    
    for i in range(remaining):
        global _shutdown_requested
        if _shutdown_requested:
            print("[Shutdown] Requested. Stopping generation.")
            return existing_samples
        
        language = random.choice(SUPPORTED_LANGUAGES)
        seed = random.randint(0, 2**32 - 1)
        
        result = NEGATIVE_GENERATOR(language, seed)
        
        # Create file path
        ext_map = {"python": "py", "javascript": "js", "typescript": "ts", "java": "java", "go": "go"}
        ext = ext_map.get(language, "py")
        # Count existing negative samples to determine index
        neg_idx = len([s for s in existing_samples if s.label == "negative"])
        file_name = f"clean_{neg_idx + 1:03d}.{ext}"
        file_path = f"negative/clean/{file_name}"
        full_path = dataset_dir / file_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write source file atomically
        temp_file = full_path.with_suffix('.tmp')
        temp_file.write_text(result["code"])
        temp_file.replace(full_path)
        
        # Compute hash
        sha256 = compute_sha256(result["code"])
        
        # Check for duplicate hash
        if sha256 in existing_hashes:
            print(f"  Duplicate hash detected, skipping sample")
            continue
        existing_hashes.add(sha256)
        
        # Create metadata
        sample_index = POSITIVE_COUNT + len([s for s in existing_samples if s.label == "negative"]) + 1
        sample_id = f"DS-B-{sample_index:04d}"
        metadata = SampleMetadata(
            sample_id=sample_id,
            language=language,
            cwe="NONE",
            category="clean",
            label="negative",
            generator_model=GROQ_MODEL,
            generation_prompt="Generate clean secure code with no intentional vulnerabilities",
            ground_truth="No intentional vulnerability present. Code follows security best practices.",
            file_path=file_path,
            sha256=sha256,
            vulnerability_type="NONE",
            severity="NONE",
            description=result["description"],
            expected_detection=False,
            temperature=0.1,
            max_tokens=512,
        )
        
        # Persist metadata immediately
        existing_samples.append(metadata)
        _append_metadata_atomic(existing_samples, Path("dataset/dataset-b/metadata.csv"), Path("dataset/dataset-b/metadata.json"))
        
        time.sleep(API_CALL_DELAY)
        
        if _shutdown_requested:
            print("[Shutdown] Requested. Stopping generation.")
            return existing_samples
    
    return existing_samples


def write_metadata_csv(samples: List[SampleMetadata], csv_path: Path):
    """Write metadata to CSV."""
    fieldnames = [
        "sample_id", "language", "cwe", "category", "label",
        "generator_model", "generation_prompt", "ground_truth",
        "file_path", "sha256", "generator_provider", "temperature",
        "top_p", "max_tokens", "prompt_version", "timestamp",
        "generation_method", "dataset_version", "vulnerability_type",
        "severity", "description", "expected_detection",
        "expected_patch_types"
    ]
    
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for sample in samples:
            row = asdict(sample)
            row['expected_patch_types'] = json.dumps(row['expected_patch_types'])
            writer.writerow(row)


def check_duplicates(samples: List[SampleMetadata]) -> tuple[int, int]:
    """Check for duplicate hashes. Returns (unique_count, duplicate_count)."""
    seen = set()
    duplicates = 0
    for sample in samples:
        if sample.sha256 in seen:
            duplicates += 1
        else:
            seen.add(sample.sha256)
    return len(seen), duplicates


def main():
    print("=" * 70)
    print(f"  Dataset B Generator v{DATASET_VERSION}")
    print(f"  Target: {TOTAL_SAMPLES} samples ({POSITIVE_COUNT} positive, {NEGATIVE_COUNT} negative)")
    print("=" * 70)
    
    # Set seed for reproducibility
    random.seed(GENERATION_CONFIG["random_seed"])
    
    dataset_dir = Path("dataset/dataset-b")
    csv_path = Path("dataset/dataset-b/metadata.csv")
    json_path = Path("dataset/dataset-b/metadata.json")
    
    # Ensure dataset directories exist
    dataset_dir.mkdir(parents=True, exist_ok=True)
    (dataset_dir / "positive").mkdir(parents=True, exist_ok=True)
    for cat_key in POSITIVE_CATEGORIES.keys():
        (dataset_dir / "positive" / cat_key).mkdir(parents=True, exist_ok=True)
    (dataset_dir / "negative" / "clean").mkdir(parents=True, exist_ok=True)
    
    print("\n[1/3] Generating positive samples...")
    all_samples = generate_positive_samples(dataset_dir, csv_path, json_path)
    pos_count = len([s for s in all_samples if s.label == 'positive'])
    print(f"  Generated {pos_count} positive samples")
    
    print("\n[2/3] Generating negative samples...")
    all_samples = generate_negative_samples(dataset_dir, csv_path, json_path)
    pos_count = len([s for s in all_samples if s.label == 'positive'])
    neg_count = len([s for s in all_samples if s.label == 'negative'])
    print(f"  Generated {pos_count} positive, {neg_count} negative samples")
    
    # Check duplicates
    print("\n[3/3] Checking duplicates...")
    unique_count, duplicate_count = check_duplicates(all_samples)
    print(f"  Unique: {unique_count}, Duplicates rejected: {duplicate_count}")
    
    # Metadata already written incrementally, just verify final state
    print(f"\nDataset B generation complete!")
    pos_count = len([s for s in all_samples if s.label == 'positive'])
    neg_count = len([s for s in all_samples if s.label == 'negative'])
    print(f"  Total samples: {len(all_samples)}")
    print(f"  Positive: {pos_count}")
    print(f"  Negative: {neg_count}")
    print(f"  Unique: {unique_count}")
    print(f"  Metadata: {csv_path}")
    print(f"  JSON: {json_path}")
    
    # Category summary
    cat_counts = {}
    for s in all_samples:
        if s.label == "positive":
            cat_counts[s.category] = cat_counts.get(s.category, 0) + 1
    print("\nCategory distribution:")
    for cat, count in sorted(cat_counts.items()):
        print(f"  {cat}: {count}")


if __name__ == "__main__":
    main()