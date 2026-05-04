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
        audit_log_file: str = "security_audit.log"
    ):
        self.allowed_commands = allowed_commands or []
        self.blocked_patterns = [re.compile(p) for p in (blocked_patterns or [])]
        self.max_calls_per_minute = max_calls_per_minute
        self.max_total_calls = max_total_calls
        self.max_arg_length = max_arg_length
        self.dry_run = dry_run
        self.audit_log_file = audit_log_file
        
        # State tracking
        self._call_history: List[float] = []
        self._total_calls = 0

    def _log_audit(self, event_type: str, func_name: str, details: str, args: tuple, kwargs: dict):
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "action": "BLOCKED" if not self.dry_run else "LOGGED_ONLY",
            "function": func_name,
            "details": details,
            "args_preview": str(args)[:200],
            "kwargs_preview": str(kwargs)[:200]
        }
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

    def validate(self, func_name: str, *args, **kwargs):
        self._enforce_quotas(func_name, args, kwargs)

        all_strings = [str(a) for a in args] + [str(v) for v in kwargs.values()]
        
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
            return func(*args, **kwargs)
        return wrapper
    return decorator
