// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#define MAX_ENTRIES 10000

static int ifindex;
static struct xdp_program *prog;
static int map_fd;
static volatile int keep_running = 1;

static void int_exit(int sig)
{
    keep_running = 0;
}

static void print_usage(char *prog_name)
{
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -i, --interface <ifname>    Interface to attach XDP program to\n");
    printf("  -h, --help                  Display this help and exit\n");
}

static void print_ip_stats(int map_fd)
{
    __u32 key, next_key;
    __u64 value;
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr ip_addr;

    printf("\n%-20s %-10s\n", "IP Address", "TCP Packets");
    printf("----------------------------------------\n");

    key = 0;
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            ip_addr.s_addr = next_key;
            inet_ntop(AF_INET, &ip_addr, ip_str, INET_ADDRSTRLEN);
            printf("%-20s %-10llu\n", ip_str, value);
        }
        key = next_key;
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    struct xdp_program *prog;
    int err, opt;
    char *ifname = NULL;
    char filename[256];

    struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    /* Parse command line arguments */
    while ((opt = getopt_long(argc, argv, "i:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            ifname = optarg;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
    }

    if (!ifname) {
        fprintf(stderr, "Error: Interface name is required\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Get interface index */
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Error: Interface '%s' not found\n", ifname);
        return EXIT_FAILURE;
    }

    /* Set up signal handler */
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    /* Load XDP program */
    snprintf(filename, sizeof(filename), "tcp_counter.o");
    prog = xdp_program__open_file(filename, "tcp_counter_func", NULL);
    if (!prog) {
        fprintf(stderr, "Error: Failed to load XDP program from %s\n", filename);
        return EXIT_FAILURE;
    }

    /* Attach XDP program to interface */
    err = xdp_program__attach(prog, ifindex, XDP_MODE_NATIVE, 0);
    if (err) {
        fprintf(stderr, "Error: Failed to attach XDP program to interface: %s\n", strerror(-err));
        xdp_program__close(prog);
        return EXIT_FAILURE;
    }

    printf("XDP program attached to interface %s (ifindex %d)\n", ifname, ifindex);

    /* Get map file descriptor */
    map_fd = bpf_object__find_map_fd_by_name(xdp_program__bpf_obj(prog), "tcp_counter_map");
    if (map_fd < 0) {
        fprintf(stderr, "Error: Failed to find map 'tcp_counter_map'\n");
        xdp_program__detach(prog, ifindex, XDP_MODE_NATIVE, 0);
        xdp_program__close(prog);
        return EXIT_FAILURE;
    }

    printf("Press Ctrl+C to stop and show statistics\n");

    /* Main loop to periodically print statistics */
    while (keep_running) {
        print_ip_stats(map_fd);
        sleep(2);
    }

    /* Cleanup */
    printf("Detaching XDP program from interface %s\n", ifname);
    xdp_program__detach(prog, ifindex, XDP_MODE_NATIVE, 0);
    xdp_program__close(prog);

    return EXIT_SUCCESS;
} 