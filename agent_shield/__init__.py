import re
import logging
import json
import time
from functools import wraps
from typing import List, Callable, Dict, Optional, Any
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent-shield")

class SecurityException(Exception):
    pass

class QuotaExceededException(Exception):
    pass

class ThreatSignatures:
    BASH_INJECTION = r"(;|\&\&|\||>|<|\$\(|\`)"
    PATH_TRAVERSAL = r"(\.\./|\.\.\\)"
    SQL_INJECTION = r"(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR 1=1)\b)"
    PROMPT_LEAKS = r"(?i)(ignore previous instructions|system prompt|you are a)"

class Policy:
    def __init__(
        self, 
        allowed_commands: List[str] = None, 
        blocked_patterns: List[str] = None,
        max_calls_per_minute: int = None,
        max_total_calls: int = None,
        max_arg_length: int = 1000,
        dry_run: bool = False,
        audit_log_file: str = "security_audit.log",
        honey_tokens: List[str] = None,
        sensitive_env_vars: List[str] = None,
        redact_output: bool = True,
        output_redaction_patterns: List[str] = None
    ):
        self.allowed_commands = allowed_commands or []
        self.blocked_patterns = [re.compile(p) for p in (blocked_patterns or [])]
        self.max_calls_per_minute = max_calls_per_minute
        self.max_total_calls = max_total_calls
        self.max_arg_length = max_arg_length
        self.dry_run = dry_run
        self.audit_log_file = audit_log_file
        self.honey_tokens = honey_tokens or []
        self.sensitive_env_vars = sensitive_env_vars or ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "SECRET_KEY"]
        self.redact_output = redact_output
        self.output_redaction_patterns = [re.compile(p) for p in (output_redaction_patterns or [r"\b\d{3}-\d{2}-\d{4}\b", r"(?i)(password|passwd|secret|key)\s*=\s*[^\s]+"])]
        
        # State tracking
        self._call_history: List[float] = []
        self._total_calls = 0

    def _log_audit(self, event_type: str, func_name: str, details: str, args: tuple, kwargs: dict, output: Any = None):
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "action": "BLOCKED" if not self.dry_run else "LOGGED_ONLY",
            "function": func_name,
            "details": details,
            "args_preview": str(args)[:200],
            "kwargs_preview": str(kwargs)[:200]
        }
        if output:
            event["output_preview"] = str(output)[:200]
            
        try:
            with open(self.audit_log_file, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.error(f"Failed to write to audit log: {e}")

    def _enforce_quotas(self, func_name: str, args: tuple, kwargs: dict):
        now = time.time()
        self._total_calls += 1
        
        if self.max_total_calls and self._total_calls > self.max_total_calls:
            msg = f"Absolute execution quota exceeded ({self.max_total_calls})"
            self._log_audit("QUOTA_VIOLATION", func_name, msg, args, kwargs)
            if not self.dry_run:
                raise QuotaExceededException(msg)

        if self.max_calls_per_minute:
            # Clean up old history
            self._call_history = [t for t in self._call_history if now - t < 60]
            self._call_history.append(now)
            if len(self._call_history) > self.max_calls_per_minute:
                msg = f"Rate limit exceeded ({self.max_calls_per_minute} calls/min)"
                self._log_audit("RATE_LIMIT_VIOLATION", func_name, msg, args, kwargs)
                if not self.dry_run:
                    raise QuotaExceededException(msg)

    def _scrub_output(self, output: Any) -> Any:
        if not self.redact_output or not isinstance(output, str):
            return output
            
        scrubbed = output
        for pattern in self.output_redaction_patterns:
            scrubbed = pattern.sub("[REDACTED]", scrubbed)
        return scrubbed

    def validate(self, func_name: str, *args, **kwargs):
        self._enforce_quotas(func_name, args, kwargs)

        all_strings = [str(a) for a in args] + [str(v) for v in kwargs.values()]
        
        # Check for Honey Tokens
        for s in all_strings:
            for token in self.honey_tokens:
                if token in s:
                    msg = f"Honey token '{token}' detected in arguments. Possible probe or leak."
                    self._log_audit("HONEY_TOKEN_DETECTION", func_name, msg, args, kwargs)
                    if not self.dry_run:
                        raise SecurityException(msg)

        # Check for Sensitive Env Vars
        import os
        for env_var in self.sensitive_env_vars:
            val = os.getenv(env_var)
            if val and len(val) > 4: # Only check if value is substantial
                for s in all_strings:
                    if val in s:
                        msg = f"Sensitive environment variable value ({env_var}) detected in arguments."
                        self._log_audit("ENV_VAR_LEAK", func_name, msg, args, kwargs)
                        if not self.dry_run:
                            raise SecurityException(msg)

        for s in all_strings:
            if len(s) > self.max_arg_length:
                msg = f"Argument length ({len(s)}) exceeds maximum allowed ({self.max_arg_length})"
                self._log_audit("CONSTRAINT_VIOLATION", func_name, msg, args, kwargs)
                if not self.dry_run:
                    raise SecurityException(msg)

            for pattern in self.blocked_patterns:
                if pattern.search(s):
                    msg = f"Input matches blocked security pattern: {pattern.pattern}"
                    self._log_audit("PATTERN_VIOLATION", func_name, msg, args, kwargs)
                    if not self.dry_run:
                        raise SecurityException(msg)

        if self.allowed_commands and args:
            base_cmd = str(args[0]).split()[0]
            if base_cmd not in self.allowed_commands:
                msg = f"Command '{base_cmd}' is not in allowed list"
                self._log_audit("COMMAND_VIOLATION", func_name, msg, args, kwargs)
                if not self.dry_run:
                    raise SecurityException(msg)

def shield(policy: Policy):
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger.info(f"Agent Shield intercepting call to {func.__name__}")
            policy.validate(func.__name__, *args, **kwargs)
            result = func(*args, **kwargs)
            
            # Post-execution output scrubbing
            if policy.redact_output:
                scrubbed_result = policy._scrub_output(result)
                if scrubbed_result != result:
                    logger.warning(f"Agent Shield redacted sensitive information from {func.__name__} output")
                    policy._log_audit("OUTPUT_REDACTION", func.__name__, "Sensitive info redacted from output", args, kwargs, output=result)
                    return scrubbed_result
            return result
        return wrapper
    return decorator
