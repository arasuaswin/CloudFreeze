"""
CloudFreeze v7: Shared Utilities
=================================
Shared helpers used by all three Lambda functions:
  - lambda_function.py   (Kill-Switch)
  - lambda_forensic.py   (Forensic)
  - lambda_restore.py    (Restore)

Deduplicates: JSONFormatter + retry_with_backoff + CircuitBreaker

v7 Fixes:
  ✅ Fix 7:  Full jitter added to retry backoff (AWS recommended strategy)
  ✅ Fix 20: ConnectionError/OSError added to retryable exceptions

v7 Fixes:
  ✅ Fix A: CircuitBreaker class — detects sustained API throttling
  ✅ Fix H: Enhanced retry — max_retries increased to 5, circuit breaker integration
"""

import json
import time
import random
import logging
import functools
from botocore.exceptions import ClientError


# ═══════════════════════════════════════════════════════════════════════════════
#  STRUCTURED JSON LOGGING — CloudWatch Insights Compatible
# ═══════════════════════════════════════════════════════════════════════════════

class JSONFormatter(logging.Formatter):
    """Formats log records as JSON for structured CloudWatch Insights queries."""
    def __init__(self, module_name="cloudfreeze"):
        super().__init__()
        self.module_name = module_name

    def format(self, record):
        # Use datetime for microsecond-precision timestamps (%f not supported by time.strftime in 3.14+)
        from datetime import datetime, timezone
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        log_entry = {
            "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "function": record.funcName,
            "message": record.getMessage(),
            "module": self.module_name,
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, default=str)


def setup_json_logging(module_name="cloudfreeze"):
    """Configures the root logger with structured JSON formatting."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    if logger.handlers:
        for handler in logger.handlers:
            handler.setFormatter(JSONFormatter(module_name))
    return logger


# ═══════════════════════════════════════════════════════════════════════════════
#  v7 CIRCUIT BREAKER — Detects Sustained API Throttling
# ═══════════════════════════════════════════════════════════════════════════════

class CircuitBreaker:
    """
    v7 Fix A: Tracks consecutive AWS API failures during a single Lambda
    invocation. When the failure threshold is hit, the circuit "opens" and
    subsequent calls are short-circuited to prevent the "API hurricane" —
    where 50+ concurrent Lambdas hammer a throttled API.

    Usage:
        cb = CircuitBreaker(failure_threshold=5)
        # In your API call wrapper:
        if cb.is_tripped():
            return {"status": "DEFERRED", "reason": "Circuit breaker open"}
        try:
            result = ec2_client.some_call(...)
            cb.record_success()
        except ClientError:
            cb.record_failure()
    """
    def __init__(self, failure_threshold=5):
        self.failures = 0
        self.threshold = failure_threshold
        self.is_open = False
        self._logger = logging.getLogger()

    def record_failure(self, error_code=""):
        """Record a failure. Opens circuit if threshold is reached."""
        self.failures += 1
        if self.failures >= self.threshold and not self.is_open:
            self.is_open = True
            self._logger.critical(
                f"CIRCUIT BREAKER OPEN — {self.failures} consecutive API failures "
                f"(threshold: {self.threshold}). Last error: {error_code}. "
                f"Remaining actions will be deferred."
            )

    def record_success(self):
        """Record a success. Resets the failure counter."""
        self.failures = 0

    def is_tripped(self):
        """Returns True if the circuit breaker is open (too many failures)."""
        return self.is_open


# ═══════════════════════════════════════════════════════════════════════════════
#  RETRY HELPER — Exponential Backoff with Full Jitter (AWS Recommended)
# ═══════════════════════════════════════════════════════════════════════════════

def retry_with_backoff(max_retries=5, base_delay=1.0, retryable_errors=None, circuit_breaker=None):
    """
    Decorator: retries a function on transient AWS errors with exponential backoff
    and FULL JITTER (AWS recommended strategy to prevent thundering herd).

    v7 Fix 7:  Added random jitter to prevent concurrent retry stampede.
    v7 Fix 20: Added ConnectionError/OSError to retryable exception types.
    v7   Fix H:  Increased max_retries from 3 to 5 for mass-event resilience.
                 Added optional circuit_breaker integration.
    """
    if retryable_errors is None:
        retryable_errors = [
            "Throttling", "ThrottlingException", "TooManyRequestsException",
            "RequestLimitExceeded", "ServiceUnavailable", "InternalError",
            "RequestTimeout", "EC2ThrottledException",
        ]

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            logger = logging.getLogger()
            for attempt in range(max_retries + 1):
                try:
                    result = func(*args, **kwargs)
                    # v7: Record success on circuit breaker if provided
                    if circuit_breaker is not None:
                        circuit_breaker.record_success()
                    return result
                except ClientError as e:
                    error_code = e.response["Error"]["Code"]
                    # v7: Record failure on circuit breaker
                    if circuit_breaker is not None:
                        circuit_breaker.record_failure(error_code)
                    if error_code in retryable_errors and attempt < max_retries:
                        # v7 Fix 7: Full jitter — random delay between 0 and exponential cap
                        delay = random.uniform(0, base_delay * (2 ** attempt))
                        logger.warning(
                            f"Retry {attempt + 1}/{max_retries} for {func.__name__} "
                            f"after {error_code}, waiting {delay:.2f}s (jittered)"
                        )
                        time.sleep(delay)
                        last_exception = e
                    else:
                        raise
                except (ConnectionError, OSError) as e:
                    # v7 Fix 20: Retry on network-level failures
                    if circuit_breaker is not None:
                        circuit_breaker.record_failure("ConnectionError")
                    if attempt < max_retries:
                        delay = random.uniform(0, base_delay * (2 ** attempt))
                        logger.warning(
                            f"Retry {attempt + 1}/{max_retries} for {func.__name__} "
                            f"after connection error: {e}, waiting {delay:.2f}s"
                        )
                        time.sleep(delay)
                        last_exception = e
                    else:
                        raise
                except Exception as e:
                    if attempt < max_retries and "timed out" in str(e).lower():
                        if circuit_breaker is not None:
                            circuit_breaker.record_failure("Timeout")
                        delay = random.uniform(0, base_delay * (2 ** attempt))
                        logger.warning(
                            f"Retry {attempt + 1}/{max_retries} for {func.__name__} "
                            f"after timeout, waiting {delay:.2f}s"
                        )
                        time.sleep(delay)
                        last_exception = e
                    else:
                        raise
            raise last_exception
        return wrapper
    return decorator


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: NACL RULE NUMBER — Collision-Avoidant Hash (Fix: NACL Collision Bug)
# ═══════════════════════════════════════════════════════════════════════════════

def nacl_rule_number(ip_address, existing_rules=None):
    """
    Generate a NACL rule number from an IP address with collision avoidance.

    v7 Bug: Used `50 + (last_octet % 40)` → only 40 unique slots → collisions.
    v7 Fix: Uses full IP hash with 200-slot range (50-249) + linear probing
    if collision with a DIFFERENT IP is detected.

    Args:
        ip_address:     The IP to generate a rule number for (e.g. "10.0.1.45")
        existing_rules: Optional dict of {rule_number: cidr_block} for existing rules

    Returns:
        int: A rule number in range 50-249, collision-free if existing_rules provided
    """
    import hashlib

    RANGE_START = 50
    RANGE_SIZE = 200  # 200 unique slots (50-249)

    # Hash the full IP, not just last octet
    ip_hash = int(hashlib.sha256(ip_address.encode()).hexdigest(), 16)
    base_rule = RANGE_START + (ip_hash % RANGE_SIZE)

    if existing_rules is None:
        return base_rule

    # Linear probing for collision avoidance
    rule_num = base_rule
    for _ in range(RANGE_SIZE):
        if rule_num not in existing_rules:
            return rule_num  # Free slot
        # Check if existing rule is for the SAME IP (not a collision)
        existing_cidr = existing_rules.get(rule_num, "")
        if ip_address in existing_cidr:
            return rule_num  # Same IP, reuse the rule
        # Collision with different IP — probe next slot
        rule_num = RANGE_START + ((rule_num - RANGE_START + 1) % RANGE_SIZE)

    # All 200 slots full (extremely unlikely) — fall back to base
    return base_rule


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: ENTROPY SCORE — Shannon Entropy for Encryption Detection
# ═══════════════════════════════════════════════════════════════════════════════

def entropy_score(data):
    """
    Calculate Shannon entropy of binary data (0.0 to 8.0 for bytes).

    Encrypted/compressed data has entropy > 7.9. Normal text is 3.5-5.0.
    Used by the instance agent to detect non-KMS local encryption
    (OpenSSL, GPG, etc.) that bypasses AWS API monitoring.

    Args:
        data: bytes object to analyze

    Returns:
        float: Shannon entropy (0.0 = uniform, 8.0 = maximum randomness)
    """
    import math
    from collections import Counter

    if not data:
        return 0.0

    length = len(data)
    freq = Counter(data)
    entropy = 0.0

    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: S3 RATE COUNTER — Bulk Operation Detection
# ═══════════════════════════════════════════════════════════════════════════════

class S3RateCounter:
    """
    In-memory rolling counter for S3 operations, similar to KMS rate counting.
    Tracks S3 DeleteObject/PutObject calls per principal per time window.

    When a principal exceeds the threshold (e.g., 50 deletes in 60s),
    the counter returns True to trigger quarantine.
    """

    def __init__(self, threshold=50, window_seconds=60):
        self.threshold = threshold
        self.window = window_seconds
        self._counters = {}  # {principal: [(timestamp, count), ...]}

    def increment(self, principal_id):
        """
        Increment counter for a principal. Returns True if threshold breached.
        """
        now = time.time()
        window_key = int(now) // self.window

        if principal_id not in self._counters:
            self._counters[principal_id] = {}

        counters = self._counters[principal_id]

        # Expire old windows
        expired = [k for k in counters if k < window_key - 1]
        for k in expired:
            del counters[k]

        # Increment current window
        counters[window_key] = counters.get(window_key, 0) + 1

        return counters[window_key] >= self.threshold

    def reset(self):
        """Reset all counters."""
        self._counters = {}
