#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/in.h>
#include <net/if.h>

struct hopper_opt {
    __le16 in_p;
    __le16 min_p;
    __le16 max_p;
};
struct event {
    __u32 ifindex;
    __be32 ipv4_src;
    __be32 ipv4_dest;
    __be16 port_src;
    __be16 port_dest;
    __be16 port_alter;
};

#endif  // __COMMON_H__
