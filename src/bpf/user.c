#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <unistd.h>

#include "common.h"

#define CONFIG_MAP "/sys/fs/bpf/hopper/map/config"

#define IFNAME "outer_veth"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    libbpf_set_print(libbpf_print_fn);

    int key = if_nametoindex(IFNAME);
    struct hopper_opt opt = {0};
    struct bpf_map_info info;
    __u32 info_len = sizeof(info);

    assert(key);
    strncpy(opt.ifname, IFNAME, IF_NAMESIZE);
    opt.in_p = 8080;
    opt.min_p = 9000;
    opt.max_p = 9999;

    int fd = bpf_obj_get(CONFIG_MAP);
    if (fd < 0) {
        close(fd);
        fprintf(stderr, "WARN: Failed to open bpf map file:%s err(%d):%s\n", CONFIG_MAP, errno,
                strerror(errno));
        return -1;
    }

    int err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
    if (err) {
        close(fd);
        fprintf(stderr, "ERR: %s() can't get info - %s\n", __func__, strerror(errno));
        return -1;
    }

    bpf_map_get_info_by_fd(fd, &info, &info_len);
    printf("Name: %s\tID: %d\n", info.name, info.id);
    bpf_map_update_elem(fd, &key, &opt, BPF_ANY);

    close(fd);
    return 0;
}
