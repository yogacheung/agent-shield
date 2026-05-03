import re
import logging
from functools import wraps
from typing import List, Callable, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent-shield")

class SecurityException(Exception):
    pass

class Policy:
    def __init__(self, allowed_commands: List[str] = None, blocked_patterns: List[str] = None):
        self.allowed_commands = allowed_commands or []
        self.blocked_patterns = [re.compile(p) for p in (blocked_patterns or [])]

    def validate(self, func_name: str, *args, **kwargs):
        # Flatten all string arguments for regex checking
        all_strings = [str(a) for a in args] + [str(v) for v in kwargs.values()]
        
        for s in all_strings:
            for pattern in self.blocked_patterns:
                if pattern.search(s):
                    logger.warning(f"[BLOCKED] Security violation in {func_name}. Matched pattern: {pattern.pattern}")
                    raise SecurityException(f"Input matches blocked security pattern.")

        # Command whitelisting logic (if applicable to the argument)
        if self.allowed_commands and args:
            base_cmd = str(args[0]).split()[0]
            if base_cmd not in self.allowed_commands:
                logger.warning(f"[BLOCKED] Command '{base_cmd}' not in allowed list: {self.allowed_commands}")
                raise SecurityException(f"Command '{base_cmd}' is not permitted.")

def shield(policy: Policy):
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger.info(f"Agent Shield intercepting call to {func.__name__}")
            policy.validate(func.__name__, *args, **kwargs)
            return func(*args, **kwargs)
        return wrapper
    return decorator
