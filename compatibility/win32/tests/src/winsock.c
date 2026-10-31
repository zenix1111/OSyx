/* Target F: Winsock over the OSyx network stack: WSAStartup, name
 * resolution, TCP echo with the host test server (10.0.2.2), a listening
 * socket on loopback, UDP, error codes, WSACleanup.
 * Usage: winsock.exe <tcp echo port> <udp echo port> */
#include <winsock2.h> /* before windows.h (common.h) */
#include "common.h"

static int parse_port(const char *s) {
    int v = 0;
    while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
    return v;
}

/* The two numbers after the program name on the command line. */
static void ports(int *tcp, int *udp) {
    const char *c = GetCommandLineA();
    while (*c && *c != ' ') c++;
    while (*c == ' ') c++;
    *tcp = parse_port(c);
    while (*c && *c != ' ') c++;
    while (*c == ' ') c++;
    *udp = parse_port(c);
}

void __stdcall start(void) {
    int tcp_port, udp_port;
    ports(&tcp_port, &udp_port);
    WSADATA wsa;
    check_eq("WSAStartup(2.2)", WSAStartup(MAKEWORD(2, 2), &wsa), 0);
    check_eq("negotiated version", wsa.wVersion, MAKEWORD(2, 2));

    struct hostent *he = gethostbyname("example.com");
    check("gethostbyname(\"example.com\") through the OSyx resolver", he != NULL && he->h_length == 4 && he->h_addr_list[0] != NULL);
    he = gethostbyname("no-such-host.invalid");
    check("unknown host fails", he == NULL);
    check_eq("... with WSAHOST_NOT_FOUND", WSAGetLastError(), WSAHOST_NOT_FOUND);

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    check_eq("getaddrinfo(\"example.com\", \"80\")", getaddrinfo("example.com", "80", &hints, &res), 0);
    check("... a TCP stream result",
          res != NULL && res->ai_family == AF_INET && res->ai_socktype == SOCK_STREAM &&
              res->ai_protocol == IPPROTO_TCP && res->ai_addrlen == sizeof(struct sockaddr_in));
    if (res) freeaddrinfo(res);
    struct addrinfo ph = {0}, *pr = NULL;
    ph.ai_flags = AI_PASSIVE;
    ph.ai_family = AF_INET;
    check_eq("getaddrinfo(NULL, \"8125\", AI_PASSIVE)", getaddrinfo(NULL, "8125", &ph, &pr), 0);
    check("... the wildcard address",
          pr != NULL && ((struct sockaddr_in *)pr->ai_addr)->sin_addr.s_addr == htonl(INADDR_ANY) &&
              ((struct sockaddr_in *)pr->ai_addr)->sin_port == htons(8125));
    if (pr) freeaddrinfo(pr);
    res = NULL;
    check_eq("getaddrinfo(NULL, \"80\", NULL)", getaddrinfo(NULL, "80", NULL, &res), 0);
    check("... a loopback TCP stream by default",
          res != NULL && res->ai_socktype == SOCK_STREAM && res->ai_protocol == IPPROTO_TCP &&
              ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    if (res) freeaddrinfo(res);
    res = NULL;
    check_eq("getaddrinfo(NULL, \"https\", NULL)", getaddrinfo(NULL, "https", NULL, &res), 0);
    check("... resolves the named service to port 443",
          res != NULL && ((struct sockaddr_in *)res->ai_addr)->sin_port == htons(443));
    if (res) freeaddrinfo(res);
    res = NULL;
    check_eq("getaddrinfo(NULL, \"no-such-service\", NULL)",
             getaddrinfo(NULL, "no-such-service", NULL, &res), WSATYPE_NOT_FOUND);

    struct addrinfo nh = {0}, *nr = NULL;
    nh.ai_family = AF_INET;
    nh.ai_flags = AI_NUMERICHOST;
    check_eq("getaddrinfo(\"example.com\", \"80\", AI_NUMERICHOST)",
             getaddrinfo("example.com", "80", &nh, &nr), WSAHOST_NOT_FOUND);
    check_eq("getaddrinfo(\"10.0.0.1\", \"80\", AI_NUMERICHOST)",
             getaddrinfo("10.0.0.1", "80", &nh, &nr), 0);
    check("... the numeric address",
          nr != NULL && ((struct sockaddr_in *)nr->ai_addr)->sin_addr.s_addr == inet_addr("10.0.0.1"));
    if (nr) freeaddrinfo(nr);
    nr = NULL;
    struct addrinfo ns = {0};
    ns.ai_family = AF_INET;
    ns.ai_flags = AI_NUMERICSERV;
    check_eq("getaddrinfo(\"10.0.0.1\", \"http\", AI_NUMERICSERV)",
             getaddrinfo("10.0.0.1", "http", &ns, &nr), WSAHOST_NOT_FOUND);
    check_eq("getaddrinfo(\"10.0.0.1\", \"8080\", AI_NUMERICSERV)",
             getaddrinfo("10.0.0.1", "8080", &ns, &nr), 0);
    check("... the numeric port", nr != NULL && ((struct sockaddr_in *)nr->ai_addr)->sin_port == htons(8080));
    if (nr) freeaddrinfo(nr);

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    check("socket(AF_INET, SOCK_STREAM)", s != INVALID_SOCKET);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((u_short)tcp_port);
    a.sin_addr.s_addr = inet_addr("10.0.2.2");
    check_eq("connect to the host echo server", connect(s, (struct sockaddr *)&a, sizeof a), 0);
    check_eq("connect again on the connected socket fails", connect(s, (struct sockaddr *)&a, sizeof a), SOCKET_ERROR);
    check_eq("... with WSAEISCONN", WSAGetLastError(), WSAEISCONN);
    check_eq("recv of zero bytes returns at once", recv(s, NULL, 0, 0), 0);
    static const char msg[] = "hello from a Winsock program on OSyx";
    check_eq("send", send(s, msg, sizeof msg - 1, 0), sizeof msg - 1);
    char buf[128];
    int got = 0;
    while (got < (int)sizeof msg - 1) {
        int n = recv(s, buf + got, sizeof buf - got, 0);
        if (n <= 0) break;
        got += n;
    }
    check("recv returns the echo", got == sizeof msg - 1 && mem_eq(buf, msg, got));
    check_eq("closesocket", closesocket(s), 0);
    check_eq("closesocket twice fails", closesocket(s), SOCKET_ERROR);
    check_eq("... with WSAENOTSOCK", WSAGetLastError(), WSAENOTSOCK);

    /* Server and client on loopback (both in this thread: the client's
     * connect completes against the listen backlog). */
    SOCKET l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in la = {0};
    la.sin_family = AF_INET;
    la.sin_port = htons(8123);
    la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    check_eq("bind 127.0.0.1:8123", bind(l, (struct sockaddr *)&la, sizeof la), 0);
    check_eq("listen", listen(l, 4), 0);
    SOCKET c = socket(AF_INET, SOCK_STREAM, 0);
    check_eq("connect over loopback", connect(c, (struct sockaddr *)&la, sizeof la), 0);
    struct sockaddr_in peer;
    int plen = sizeof peer;
    int badlen = 8;
    check_eq("accept with a short addrlen fails", accept(l, (struct sockaddr *)&peer, &badlen), INVALID_SOCKET);
    check_eq("... with WSAEFAULT", WSAGetLastError(), WSAEFAULT);
    SOCKET srv = accept(l, (struct sockaddr *)&peer, &plen);
    check("accept", srv != INVALID_SOCKET && peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    check("loopback data", send(c, "ping", 4, 0) == 4 && recv(srv, buf, 4, 0) == 4 && mem_eq(buf, "ping", 4));
    check_eq("zero-length send", send(c, NULL, 0, 0), 0);
    check_eq("second send", send(c, "pong", 4, 0), 4);
    check_eq("third send", send(c, "more", 4, 0), 4);
    check("recv(MSG_WAITALL) fills the buffer",
          recv(srv, buf, 8, MSG_WAITALL) == 8 && mem_eq(buf, "pongmore", 8));
    closesocket(srv);
    closesocket(c);
    closesocket(l);

    /* Connection refused by a closed loopback port. */
    s = socket(AF_INET, SOCK_STREAM, 0);
    la.sin_port = htons(8124);
    check_eq("connect to a closed port fails", connect(s, (struct sockaddr *)&la, sizeof la), SOCKET_ERROR);
    check_eq("... with WSAECONNREFUSED", WSAGetLastError(), WSAECONNREFUSED);
    closesocket(s);

    /* A non-blocking connect failure is reported through SO_ERROR. */
    s = socket(AF_INET, SOCK_STREAM, 0);
    u_long on = 1;
    check_eq("ioctlsocket(FIONBIO)", ioctlsocket(s, FIONBIO, &on), 0);
    check_eq("non-blocking connect to a closed port", connect(s, (struct sockaddr *)&la, sizeof la), SOCKET_ERROR);
    check_eq("... WSAEWOULDBLOCK", WSAGetLastError(), WSAEWOULDBLOCK);
    fd_set ws;
    FD_ZERO(&ws);
    FD_SET(s, &ws);
    struct timeval tv = {5, 0};
    check("select waits for the failed connect", select(0, NULL, &ws, NULL, &tv) == 1 && FD_ISSET(s, &ws));
    int soerr = 0, elen = sizeof soerr;
    check_eq("getsockopt(SO_ERROR)", getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &elen), 0);
    check_eq("... WSAECONNREFUSED", soerr, WSAECONNREFUSED);
    soerr = -1;
    elen = sizeof soerr;
    check_eq("getsockopt(SO_ERROR) clears the error", getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &elen), 0);
    check_eq("... now zero", soerr, 0);
    closesocket(s);

    /* select with nothing to watch waits out its timeout; bad arguments fail. */
    fd_set none;
    FD_ZERO(&none);
    struct timeval wait_tv = {0, 20000};
    check_eq("select over empty sets waits out the timeout", select(0, &none, &none, NULL, &wait_tv), 0);
    struct timeval bad_tv = {0, 1000000};
    check_eq("select rejects tv_usec >= 1000000", select(0, &none, &none, NULL, &bad_tv), SOCKET_ERROR);
    check_eq("... with WSAEINVAL", WSAGetLastError(), WSAEINVAL);
    fd_set ex;
    FD_ZERO(&ex);
    FD_SET((SOCKET)0xdeadbeef, &ex);
    check_eq("select rejects a non-socket in exceptfds", select(0, &none, &none, &ex, &wait_tv), SOCKET_ERROR);
    check_eq("... with WSAENOTSOCK", WSAGetLastError(), WSAENOTSOCK);

    /* Option values round-trip through getsockopt. */
    SOCKET o = socket(AF_INET, SOCK_STREAM, 0);
    int en = 1, oval = 0, olen = sizeof oval;
    check_eq("setsockopt(SO_REUSEADDR)", setsockopt(o, SOL_SOCKET, SO_REUSEADDR, (const char *)&en, sizeof en), 0);
    check("getsockopt(SO_REUSEADDR) returns it",
          getsockopt(o, SOL_SOCKET, SO_REUSEADDR, (char *)&oval, &olen) == 0 && oval == 1);
    oval = 0;
    olen = sizeof oval;
    check_eq("setsockopt(SO_KEEPALIVE)", setsockopt(o, SOL_SOCKET, SO_KEEPALIVE, (const char *)&en, sizeof en), 0);
    check("getsockopt(SO_KEEPALIVE) returns it",
          getsockopt(o, SOL_SOCKET, SO_KEEPALIVE, (char *)&oval, &olen) == 0 && oval == 1);
    closesocket(o);

    /* A negative length must fail, not be read as a huge size. */
    char small[3] = {0};
    check_eq("gethostname rejects a negative length", gethostname(small, -1), SOCKET_ERROR);
    check_eq("... with WSAEFAULT", WSAGetLastError(), WSAEFAULT);
    char host[256];
    check_eq("gethostname fits the host name", gethostname(host, sizeof host), 0);

    /* Broadcast needs SO_BROADCAST; a plain socket is refused. */
    SOCKET nb = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in bc = {0};
    bc.sin_family = AF_INET;
    bc.sin_port = htons(8127);
    bc.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    check_eq("sendto broadcast without SO_BROADCAST fails",
             sendto(nb, "x", 1, 0, (struct sockaddr *)&bc, sizeof bc), SOCKET_ERROR);
    check_eq("... with WSAEACCES", WSAGetLastError(), WSAEACCES);
    closesocket(nb);

    /* UDP echo with the host. */
    SOCKET u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    a.sin_port = htons((u_short)udp_port);
    check_eq("sendto (UDP)", sendto(u, "udp!", 4, 0, (struct sockaddr *)&a, sizeof a), 4);
    DWORD timeout = 3000;
    setsockopt(u, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout);
    struct sockaddr_in from;
    int flen = sizeof from;
    int shortlen = 8;
    check_eq("recvfrom with a short fromlen fails", recvfrom(u, buf, sizeof buf, 0, (struct sockaddr *)&from, &shortlen), SOCKET_ERROR);
    check_eq("... with WSAEFAULT", WSAGetLastError(), WSAEFAULT);
    int n = recvfrom(u, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen);
    check("recvfrom gets the echo from 10.0.2.2", n == 4 && mem_eq(buf, "udp!", 4) && from.sin_addr.s_addr == inet_addr("10.0.2.2"));
    closesocket(u);

    /* getpeername works on a connected datagram socket. */
    SOCKET uc = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ca = {0};
    ca.sin_family = AF_INET;
    ca.sin_port = htons(8129);
    ca.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    check_eq("connect UDP", connect(uc, (struct sockaddr *)&ca, sizeof ca), 0);
    struct sockaddr_in cn;
    int cnlen = sizeof cn;
    check("getpeername on connected UDP",
          getpeername(uc, (struct sockaddr *)&cn, &cnlen) == 0 && cn.sin_port == htons(8129) &&
              cn.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    closesocket(uc);
    check_eq("WSACleanup", WSACleanup(), 0);
    finish("winsock");
}
