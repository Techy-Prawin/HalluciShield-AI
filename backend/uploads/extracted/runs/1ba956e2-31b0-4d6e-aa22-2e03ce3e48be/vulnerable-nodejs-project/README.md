# Vulnerable Node.js Test Project

This project intentionally contains insecure code for LOCAL security-scanner,
vulnerability-detection, patch-generation, and validation testing.

## Vulnerabilities

1. SQL Injection - CWE-89 - `/users`
2. OS Command Injection - CWE-78 - `/ping`
3. Hardcoded Secret - CWE-798 - `/config`
4. Reflected XSS - CWE-79 - `/search`

## Run locally

```bash
npm install
npm start
```

Server:
http://localhost:4000

## Example routes

- `/users?username=alice`
- `/ping?host=127.0.0.1`
- `/config`
- `/search?q=hello`

DO NOT deploy this application to a public server. It is intentionally vulnerable.
