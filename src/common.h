#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/in.h>

struct hopper_opt {
    __le16 in_p;
    __le16 min_p;
    __le16 max_p;
    char ifname[IF_NAMESIZE];
};

#endif  // __COMMON_H__
