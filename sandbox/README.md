# HalluciShield Execution Sandbox

The `sandbox` directory contains container configurations and runtime scripts for executing untrusted AI-generated code and test suites inside isolated Docker containers.

## Architecture

```
sandbox/
├── Dockerfile.sandbox    # Multi-language sandbox container image
├── runner.py             # Validation pipeline executor (runs inside container)
└── README.md             # This file
```

## Security Guarantees

### 1. Network Isolation
- Containers run with `--net=none`
- No inbound or outbound network connections possible
- Prevents data exfiltration and command-and-control communication

### 2. Privilege Reduction
- Containers execute as non-root user `sandboxuser` (UID 10001)
- All Linux capabilities dropped (`cap_drop=["ALL"]`)
- `no-new-privileges` security option prevents privilege escalation

### 3. Resource Limits
| Resource | Default | Configurable |
|----------|---------|-------------|
| CPU | 1.0 core | Yes |
| Memory | 512MB | Yes |
| Execution Timeout | 30s | Yes |
| Max Processes | 64 | Yes |
| tmpfs Size | 256MB | Yes |

### 4. Filesystem Isolation
- Temporary filesystem via tmpfs mounts (`/tmp`, `/var/tmp`)
- Workspace mounted as isolated volume
- Container filesystem is ephemeral

### 5. Automatic Cleanup
- Containers are force-removed after execution
- Temporary workspace directories are deleted
- No persistent state between validations

### 6. Host Protection
- Code is NEVER executed directly on the host
- All execution happens inside isolated containers
- Container has no access to host filesystem (except mounted workspace)

## Validation Pipeline

Each patch candidate goes through a 6-step pipeline:

1. **Repository Preparation** - Set up workspace with patch and configuration
2. **Patch Application** - Apply the candidate patch to the target file
3. **Compilation** - Compile the code (if applicable)
4. **Test Execution** - Run the test suite
5. **Security Scan** - Run security scanner (e.g., semgrep)
6. **Result Collection** - Collect and report all results

## Multi-Language Support

The sandbox supports:
- **Python** - Full support with pytest
- **JavaScript/Node.js** - Support with jest
- **Java** - Support with JUnit

## API Usage

### Validate a Single Patch

```http
POST /api/v1/vulnerabilities/{vulnerability_id}/validate-patch
Content-Type: application/json

{
  "patch": {
    "patch_id": "patch-1",
    "modified_code": "def safe_query(username):\n    cursor.execute('SELECT * FROM users WHERE id = ?', (username,))",
    "explanation": "Uses parameterized query",
    "security_strategy": "Parameterized Query",
    "assumptions": ["Database supports parameterization"],
    "expected_effect": "Prevents SQL injection",
    "potential_side_effects": ["May change query performance"]
  },
  "file_path": "app/db.py",
  "original_code": "def vulnerable_query(username):\n    cursor.execute('SELECT * FROM users WHERE id = ' + username)",
  "language": "python",
  "test_command": "python -m pytest tests/",
  "scan_command": "semgrep --config=auto app/"
}
```

### Response Format

```json
{
  "patch_id": "patch-1",
  "compilation": {
    "success": true,
    "language": "python",
    "output": "Compilation successful",
    "duration_ms": 100
  },
  "tests": {
    "success": true,
    "framework": "pytest",
    "total_tests": 5,
    "passed": 5,
    "failed": 0,
    "skipped": 0,
    "output": "5 passed in 0.5s",
    "duration_ms": 500,
    "failures": []
  },
  "security_scan": {
    "success": true,
    "scanner": "semgrep",
    "vulnerabilities_found": 0,
    "findings": [],
    "output": "No issues found",
    "duration_ms": 2000
  },
  "performance": {
    "execution_time_ms": 100,
    "memory_peak_mb": 50.0,
    "cpu_usage_percent": 25.0
  },
  "execution_time": 3000,
  "overall_success": true,
  "sandbox_security_notes": [
    "Container executed with --net=none (network isolated)",
    "Container executed as non-root user (UID 10001)",
    "CPU limit: 1.0 cores",
    "Memory limit: 512m",
    "Timeout: 30s",
    "Process limit: 64",
    "tmpfs mounts for /tmp and /var/tmp",
    "No-new-privileges security option enabled",
    "All Linux capabilities dropped",
    "Automatic container cleanup on completion"
  ]
}
```

## Configuration

### SandboxConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cpu_limit` | float | 1.0 | CPU cores limit |
| `memory_limit` | str | "512m" | Memory limit (e.g., 512m, 1g) |
| `execution_timeout` | int | 30 | Max execution time in seconds |
| `max_processes` | int | 64 | Max number of processes |
| `tmpfs_size` | str | "256m" | Size of tmpfs mount |

## Docker Requirements

- Docker Engine 20.10+ or Docker Desktop 4.0+
- Docker SDK for Python (`docker>=7.0.0`)
- Sufficient disk space for container images

## Building the Sandbox Image

The sandbox image is automatically built on first use. To build manually:

```bash
cd sandbox
docker build -t hallucishield-sandbox:latest -f Dockerfile.sandbox .
```

## Limitations

- Each validation runs in a fresh container (no shared state)
- No persistent storage between validations
- Limited to single-file patches
- Container images must be pre-built or built on first use
- Docker daemon must be running on the host

## Security Assumptions

1. **Docker daemon is trusted** - We assume the Docker daemon running on the host is not compromised
2. **Container image is trusted** - The sandbox image is built from our Dockerfile
3. **Kernel is hardened** - We assume the host kernel has standard security patches
4. **No shared namespaces** - Each container gets its own isolated namespaces
5. **Resource limits enforced** - Docker enforces CPU, memory, and process limits
6. **Network fully isolated** - `--net=none` prevents all network access
