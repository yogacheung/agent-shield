# Agent Shield 🛡️

Agent Shield is a lightweight, zero-dependency Python firewall for autonomous AI agents. It intercepts and validates tool/function calls made by LLMs before they are executed, preventing malicious or destructive actions.

## Why Agent Shield?
Autonomous agents are powerful, but giving them raw access to APIs, databases, or the filesystem is dangerous. Prompt injections can easily hijack an agent to execute `os.system("rm -rf /")` or exfiltrate data.

Agent Shield acts as a strict parameter validator and policy enforcement layer.

## Installation
```bash
pip install agent-shield
```

## Usage
```python
from agent_shield import shield, Policy

# Define a strict policy for tool execution
policy = Policy(
    allowed_commands=["ls", "echo", "cat"],
    blocked_patterns=[r";", r"&&", r"\|", r">", r"<"]
)

@shield(policy=policy)
def execute_system_command(command: str):
    import os
    return os.popen(command).read()

# Safe execution
print(execute_system_command("ls -la"))

# Blocked execution (Raises SecurityException)
print(execute_system_command("ls -la; cat /etc/passwd"))
```

## Features
- **Zero Dependencies**: Pure Python implementation.
- **Pre-configured Threat Signatures**: Built-in protection against Bash Injection, SQL Injection, Path Traversal, and Prompt Leaks.
- **Execution Quotas**: Prevent runaway agents with rate limiting and total call quotas.
- **Argument Constraints**: Enforce maximum string lengths to prevent buffer overruns or logic abuse.
- **JSON Audit Logging**: Structured logs for security monitoring and SIEM integration.
- **Dry Run Mode**: Test your security policies without breaking existing workflows.

## Usage
```python
from agent_shield import shield, Policy, ThreatSignatures

# Define a robust security policy
policy = Policy(
    allowed_commands=["ls", "echo"],
    blocked_patterns=[ThreatSignatures.BASH_INJECTION, ThreatSignatures.PROMPT_LEAKS],
    max_calls_per_minute=10,
    max_arg_length=500
)

@shield(policy=policy)
def execute_system_command(command: str):
    import os
    return os.popen(command).read()

# This will be blocked by ThreatSignatures.BASH_INJECTION
try:
    execute_system_command("ls; rm -rf /")
except Exception as e:
    print(f"Security Alert: {e}")
```

## Contributing
We welcome contributions! Please see `CONTRIBUTING.md` for details.
