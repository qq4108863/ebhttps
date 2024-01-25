// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Yusheng Zheng
//
// Based on sslsniff from BCC by Adrian Lopez & Mark Drayton.
// 15-Aug-2023   Yusheng Zheng   Created this.
#ifndef __EBHTTPS_H
#define __EBHTTPS_H

#include <sys/socket.h>
#include <netinet/in.h>


#define MAX_BUF_SIZE 8192
#define TASK_COMM_LEN 16

struct probe_SSL_data_t {
    __u64 timestamp_ns;
    __u64 delta_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 len;
    int buf_filled;
    int rw;
    char comm[TASK_COMM_LEN];
    __u8 buf[MAX_BUF_SIZE];
    int is_handshake;
};

struct hihttps_atk_list {
    struct sockaddr_storage sa; /*for cdn*/
    char *header;
    int   header_len;
    int   drop;
    int   leak;
    int   reserve;
};

struct session {
	
	unsigned int flags;             /* session flags, SESS_FL_* */
    unsigned int meth;              /*GET 1 POST 3*/
    char         *uri;
    struct hihttps_atk_list hihttps;
};



#endif /* __EBHTTPSF_H */
