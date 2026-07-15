"""Static Wazuh validation catalog and thresholds."""

from __future__ import annotations

import re


REQUIRED_FIELDS = frozenset({"id", "level", "description"})
NUMERIC_FIELDS = frozenset({"id", "level", "maxsize", "timeframe", "frequency"})
VALID_LEVELS = frozenset(range(0, 17))
RULE_ID_PATTERN = re.compile(r"^\d{1,7}$")

MAX_REGEX_LENGTH = 1000
MAX_ALTERNATION_DEPTH = 5
MAX_BACKREFERENCES = 5

COMMON_DECODERS = frozenset({
    "apache",
    "auditd",
    "cimserver",
    "dovecot",
    "kernel",
    "mysql",
    "nginx",
    "openssh",
    "ossec",
    "pam",
    "postfix",
    "proftpd",
    "roundcube",
    "sendmail",
    "snort",
    "sshd",
    "sudo",
    "suricata",
    "windows",
})

COMMON_RULESETS = frozenset({
    "access_control",
    "authentication",
    "malware_detection",
    "network_events",
    "privilege_escalation",
    "rootkit_detection",
    "system_events",
    "web-application_attacks",
    "web-application_errors",
})
