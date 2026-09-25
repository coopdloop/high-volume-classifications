"""System-1 question set asked of JEV for every log event."""

MITRE_TACTICS = {
    "recon": "Gathering information about the target environment",
    "initial-access": "Phishing, valid-account abuse, exploiting public services",
    "execution": "Running malicious code, suspicious interpreters, encoded commands",
    "persistence": "Autoruns, new services, scheduled tasks, account creation",
    "privilege-escalation": "Credential dumping, token manipulation, sudo/UAC abuse",
    "defense-evasion": "Disabling logging/AV, obfuscation, timestomping, masquerading",
    "credential-access": "LSASS access, password spraying, keylogging",
    "lateral-movement": "SMB/WinRM/RDP between hosts, PsExec-style tooling",
    "exfiltration": "Large or unusual outbound transfers, rare external destinations",
    "benign": "Normal operational or user activity",
}


def question_set() -> dict:
    return {
        "is_suspicious": {
            "type": "noul",
            "instructions": (
                "This log event shows signs of malicious or unauthorized activity, "
                "considering the asset and identity enrichment provided."
            ),
        },
        "mitre_tactic": {
            "type": "choice",
            "instructions": "The MITRE ATT&CK tactic this event best maps to.",
            "criteria": MITRE_TACTICS,
        },
        "severity": {
            "type": "score",
            "instructions": "Security severity of this event for the organization.",
            "criteria": [
                "Informational, routine activity",
                "Slightly unusual but almost certainly benign",
                "Notable anomaly warranting review",
                "Likely malicious, needs prompt investigation",
                "Critical, active compromise in progress",
            ],
        },
        "needs_context": {
            "type": "noul",
            "instructions": (
                "This event is only meaningful when correlated with other events "
                "(e.g., a single login or process start that is suspicious mainly "
                "as part of a sequence)."
            ),
        },
    }
