# Agent Shield 🛡️

Agent Shield is a lightweight, zero-dependency Python firewall for autonomous AI agents. It intercepts and validates tool/function calls made by LLMs before they are executed, preventing malicious or destructive actions.

## Why Agent Shield?
Autonomous agents are powerful, but giving them raw access to APIs, databases, or the filesystem is dangerous. Prompt injections can easily hijack an agent to execute `os.system("rm -rf /")` or exfiltrate data.

Agent Shield acts as a strict parameter validator and policy enforcement layer.

## Installation
```bash
pip install agent-shield
```

## Features
- **Zero Dependencies**: Pure Python implementation.
- **Honey Token Detection**: Detect if an LLM tries to use reserved "trap" keywords.
- **Environment Scrubbing**: Block arguments that contain sensitive environment variable values.
- **Output Shielding**: Redact PII, secrets, or credentials from the *return value* of a tool.
- **Pre-configured Threat Signatures**: Built-in protection against Bash Injection, SQL Injection, Path Traversal, and Prompt Leaks.
- **Execution Quotas**: Prevent runaway agents with rate limiting and total call quotas.
- **Argument Constraints**: Enforce maximum string lengths to prevent buffer overruns or logic abuse.
- **JSON Audit Logging**: Structured logs for security monitoring and SIEM integration.
- **Dry Run Mode**: Test your security policies without breaking existing workflows.

## Usage
```python
import os
from agent_shield import shield, Policy, ThreatSignatures

# Set a sensitive env var for the demonstration
os.environ["DATABASE_URL"] = "postgresql://admin:super-secret-pass@localhost/db"

# Define a robust security policy
policy = Policy(
    allowed_commands=["ls", "echo", "query_db"],
    blocked_patterns=[ThreatSignatures.BASH_INJECTION, ThreatSignatures.SQL_INJECTION],
    honey_tokens=["INTERNAL_DEVOPS_API"],
    max_calls_per_minute=5,
    max_arg_length=500,
    redact_output=True
)

# Usage as a Decorator
@shield(policy=policy)
def query_db(query: str):
    return f"Result for {query}"

# Usage as a Context Manager
with shield(policy):
    # Any data validation inside this block
    policy.validate("manual_check", "some user input")

# Zero-Config Deployment (Load from Environment Variables)
# SHIELD_ALLOWED_COMMANDS=ls,grep SHIELD_DRY_RUN=true python app.py
env_policy = Policy.from_env()

# 1. Blocked by ThreatSignatures.SQL_INJECTION
try:
    query_db("SELECT * FROM users WHERE id = '1' OR 1=1")
except Exception as e:
    print(f"Blocked SQLi: {e}")

# 2. Blocked by Environment Scrubbing (detects DATABASE_URL value)
try:
    query_db("postgresql://admin:super-secret-pass@localhost/db")
except Exception as e:
    print(f"Blocked Env Var Leak: {e}")

# 3. Output Redaction (SSN and Password will be scrubbed)
result = query_db("get_user_info")
print(f"Scrubbed Output: {result}")
```

## Contributing
We welcome contributions! Please see `CONTRIBUTING.md` for details.
