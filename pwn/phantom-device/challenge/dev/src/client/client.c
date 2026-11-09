/*
 * client.c — Normal AFC client (victim process)
 *
 * Links REAL libimobiledevice.so Only standard AFC API calls.
 *
 * Connection setup uses private struct definitions — test harness only.
 * A real attack targets a program that connects via idevice_new() + lockdown.
 *
 * Modes:
 *   ./client <host> <port>   — connect out (local testing with patchelf)
 *   ./client                 — use stdin fd from socat (deployed container)
 *
 * Build:
 *   gcc -g -O0 -o client client.c \
 *       -I/path/to/libimobiledevice/src -I/path/to/libimobiledevice/include \
 *       $(pkg-config --cflags --libs libimobiledevice-1.0) -lpthread
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <libimobiledevice/afc.h>
#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/service.h>

/* Private struct definitions — test harness only.
   In a real attack, the victim uses public idevice_new() + lockdownd. */
typedef pthread_mutex_t mutex_t;
struct ssl_data_private { void *session; void *ctx; };
typedef struct ssl_data_private *ssl_data_t;
struct idevice_connection_private {
    idevice_t device; int type; void *data;
    ssl_data_t ssl_data; unsigned int ssl_recv_timeout; int status;
};
struct idevice_private {
    char *udid; uint32_t mux_id; int conn_type;
    void *conn_data; int version; int device_class;
};
struct service_client_private { idevice_connection_t connection; };
#define AFC_MAGIC "CFA6LPAA"
#define AFC_MAGIC_LEN 8
typedef struct {
    char magic[AFC_MAGIC_LEN];
    uint64_t entire_length, this_length, packet_num, operation;
} AFCPacket;
struct afc_client_private {
    service_client_t parent; AFCPacket *afc_packet;
    uint32_t packet_extra; mutex_t mutex; int free_parent;
};

static void free_list(char **list) {
    if (!list) return;
    for (int i = 0; list[i]; i++) free(list[i]);
    free(list);
}

static void nop_handler(int sig) { (void)sig; }

int main(int argc, char **argv) {
    signal(SIGUSR1, nop_handler);
    signal(SIGUSR2, nop_handler);
    signal(SIGURG,  nop_handler);

    int fd;

    if (argc >= 3) {
        /* Legacy mode: connect out to host:port (local testing only) */
        const char *host = argv[1];
        int port = atoi(argv[2]);
        fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = {.sin_family=AF_INET, .sin_port=htons(port)};
        inet_pton(AF_INET, host, &a.sin_addr);
        if (connect(fd, (struct sockaddr*)&a, sizeof(a)) < 0) {
            perror("connect"); return 1;
        }
    } else {
        /* Socat mode: stdin/stdout are the player's socket.
           Dup stdin for AFC, then redirect stdout/stderr to /dev/null
           so printf debug output doesn't corrupt the binary protocol. */
        fd = dup(STDIN_FILENO);
        if (fd < 0) { perror("dup"); return 1; }
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
    }
    struct idevice_private *dev = calloc(1, sizeof(*dev));
    dev->udid = strdup("0000-0000-0000"); dev->conn_type = 1;
    struct idevice_connection_private *cn = calloc(1, sizeof(*cn));
    cn->device = (idevice_t)dev; cn->type = 1;
    cn->data = (void*)(long)fd; cn->ssl_recv_timeout = 30000;
    struct service_client_private *svc = calloc(1, sizeof(*svc));
    svc->connection = (idevice_connection_t)cn;
    struct afc_client_private *afc = calloc(1, sizeof(*afc));
    afc->parent = (service_client_t)svc;
    afc->packet_extra = 1024;
    afc->afc_packet = (AFCPacket*)malloc(sizeof(AFCPacket) + 1024);
    memset(afc->afc_packet, 0, sizeof(AFCPacket) + 1024);
    memcpy(afc->afc_packet->magic, AFC_MAGIC, AFC_MAGIC_LEN);
    pthread_mutex_init(&afc->mutex, NULL);
    afc_client_t client = (afc_client_t)afc;

    /* 
       NORMAL CLIENT CODE — a typical program browsing an iOS device.
       Only uses standard AFC API: read_directory, get_device_info,
       get_file_info, file_open, file_read, file_close.
    */

    char **dir1 = NULL, **dir2 = NULL, **dir3 = NULL;
    char **devi = NULL, **info = NULL;
    char buf[4096];
    uint32_t n = 0;
    uint64_t h1 = 0, h2 = 0, h3 = 0;

    afc_read_directory(client, "/", &dir1);
    afc_read_directory(client, "/DCIM", &dir2);

    free_list(dir1); dir1 = NULL;
    free_list(dir2); dir2 = NULL;
    raise(SIGUSR2);

    afc_get_device_info(client, &devi);
    free_list(devi); devi = NULL;
    raise(SIGURG);

    afc_get_file_info(client, "/etc/fstab", &info);
    free_list(info); info = NULL;

    afc_read_directory(client, "/var", &dir3);

    afc_file_open(client, "/etc/fstab", 2 /* AFC_FOPEN_RDONLY */, &h1);
    printf("H1=0x%016lx\n", h1); fflush(stdout);
    afc_file_read(client, h1, buf, sizeof(buf), &n);

    afc_file_open(client, "/var/log/syslog", 2, &h2);
    printf("H2=0x%016lx\n", h2); fflush(stdout);
    afc_file_read(client, h2, buf, sizeof(buf), &n);

    afc_file_open(client, "/var/log/auth.log", 2, &h3);
    printf("H3=0x%016lx\n", h3); fflush(stdout);
    raise(SIGUSR1);
    afc_file_read(client, h3, buf, sizeof(buf), &n);

    afc_file_close(client, h1);
    afc_file_close(client, h2);
    afc_file_close(client, h3);

    free_list(dir3); dir3 = NULL;

    /* Normal exit → exit() → _IO_cleanup → _IO_flush_all_lockp
       → walks FILE list starting from _IO_list_all
       → if corrupted → House of Apple 2 → system() */
    printf("EXIT\n"); fflush(stdout);
    close(fd);
    return 0;
}
