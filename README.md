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
- **Regex Blocking**: Block complex injection patterns.
- **Type Enforcement**: Ensure the LLM didn't hallucinate invalid types.
- **Audit Logging**: Log all blocked attempts for threat analysis.

## Contributing
We welcome contributions! Please see `CONTRIBUTING.md` for details.
