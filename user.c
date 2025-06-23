#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <locale.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

#define CONFIG_MAP "/sys/fs/bpf/hopper/map/config"
#define IF_MAP     "/sys/fs/bpf/hopper/map/if2name"

#define IFNAME_OUTER "outer_veth"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

void config_ifmap()
{
    struct bpf_map_info info;
    __u32 info_len = sizeof(info);

    int fd = bpf_obj_get(IF_MAP);
    if (fd < 0) {
        fprintf(stderr, "WARN: Failed to open bpf map file:%s err(%d):%s\n", IF_MAP, errno,
                strerror(errno));
        return;
    }

    int err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
    if (err) {
        fprintf(stderr, "ERR: %s() can't get info - %s\n", __func__, strerror(errno));
        return;
    }

    bpf_map_get_info_by_fd(fd, &info, &info_len);
    printf("Name: %s\tID: %d\n", info.name, info.id);

    int key = if_nametoindex(IFNAME_OUTER);
    bpf_map_update_elem(fd, &key, IFNAME_OUTER, BPF_ANY);

    close(fd);
}

void config_hopper()
{
    struct hopper_opt opt = {0};
    opt.in_p = 8080;
    opt.min_p = 9000;
    opt.max_p = 9999;

    int k = 0;
    struct bpf_map_info info;
    __u32 info_len = sizeof(info);

    int fd = bpf_obj_get(CONFIG_MAP);
    if (fd < 0) {
        fprintf(stderr, "WARN: Failed to open bpf map file:%s err(%d):%s\n", CONFIG_MAP, errno,
                strerror(errno));
        return;
    }

    int err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
    if (err) {
        fprintf(stderr, "ERR: %s() can't get info - %s\n", __func__, strerror(errno));
        return;
    }

    bpf_map_get_info_by_fd(fd, &info, &info_len);
    printf("Name: %s\tID: %d\n", info.name, info.id);

    bpf_map_update_elem(fd, &k, &opt, BPF_ANY);

    close(fd);
}

int main(int argc, char **argv)
{
    libbpf_set_print(libbpf_print_fn);

    config_ifmap();
    config_hopper();

    return 0;
}
