# Agent Shield Feature Plan 🛡️

Here is the detailed feature roadmap for `agent-shield` to make it a top-tier, highly-starred project for AI security.

## Core Pillars
1. **Zero-Dependency Core**: Maintain a pure Python standard library core to ensure it can be dropped into any project without dependency conflicts.
2. **Defense-in-Depth**: Multiple layers of security validation (Regex, Types, Quotas).
3. **Observability**: Rich audit logging for SOC/SIEM integrations.

## Extra Strong Features to Implement

### 1. Built-in Threat Signatures (Pre-configured Policies)
Instead of forcing users to write their own regexes, provide out-of-the-box policies for:
- **Bash Injection**: `(;|\&\&|\||>|<|\$\()`
- **Path Traversal**: `(\.\./|\.\.\\)`
- **SQL Injection**: `' OR 1=1`, `DROP TABLE`
- **Prompt Leaks**: "ignore previous instructions", "system prompt"

### 2. Execution Quotas (Rate Limiting)
Autonomous agents can get stuck in infinite loops, calling the same API repeatedly, which drains budgets and causes denial-of-service. 
- **Feature**: `max_calls_per_minute` and `max_total_calls`.
- **Action**: Raises a `QuotaExceededException` if the agent goes rogue.

### 3. Argument Constraints (Bounds & Length Checking)
LLMs sometimes hallucinate massively long strings or out-of-bound numbers.
- **Feature**: Define `max_len`, `min_val`, and `max_val` directly in the policy to prevent buffer overruns or logic abuse.

### 4. JSON Audit Logging
Security tools need observability.
- **Feature**: Automatically dump blocked actions, timestamps, and the triggered rule into a structured `security_audit.log` file.

### 5. "Dry Run" / Alert-Only Mode
- **Feature**: Allow the policy to just log the violation but still execute the function. This is critical for onboarding the shield into production without breaking existing agent workflows.

---
*Implementation and testing will begin immediately.*
