// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Yusheng Zheng
//
// Based on ebhttps from BCC by Adrian Lopez & Mark Drayton.
// 15-Aug-2023   Yusheng Zheng   Created this.
#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <errno.h>
#include <linux/types.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "ebhttps.skel.h"
#include "ebhttps.h"

#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "waf/httpx.h"
#include "waf/rules.h"
#include "waf/atklog.h"
#include "waf/hashmap.h"
#include "machine-learning/machine-learning.h"

#define MAX_QPS            32

static  char               g_req_buf[MAX_QPS*32000];

static struct sockaddr_storage    sa_src;
static struct sockaddr_storage    sa_dst;


#define INVALID_UID -1
#define INVALID_PID -1
#define DEFAULT_BUFFER_SIZE 8192

#define __ATTACH_UPROBE(skel, binary_path, sym_name, prog_name, is_retprobe)   \
	do {                                                                       \
	  LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = #sym_name,        \
				  .retprobe = is_retprobe);                                    \
	  skel->links.prog_name = bpf_program__attach_uprobe_opts(                 \
		  skel->progs.prog_name, env.pid, binary_path, 0, &uprobe_opts);       \
	} while (false)

#define __CHECK_PROGRAM(skel, prog_name)               \
	do {                                               \
	  if (!skel->links.prog_name) {                    \
		perror("no program attached for " #prog_name); \
		return -errno;                                 \
	  }                                                \
	} while (false)

#define __ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name,     \
								is_retprobe)                                \
	do {                                                                    \
	  __ATTACH_UPROBE(skel, binary_path, sym_name, prog_name, is_retprobe); \
	  __CHECK_PROGRAM(skel, prog_name);                                     \
	} while (false)

#define ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name)     \
	__ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, binary_path, sym_name, prog_name)  \
	__ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name, true)

volatile sig_atomic_t exiting = 0;

const char *argp_program_version = "ebhttps 1.1";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
	"Sniff SSL data.\n"
	"\n"
	"USAGE: ebhttps [OPTIONS]\n"
	"\n"
	"EXAMPLES:\n"
	"    ./ebhttps              # sniff OpenSSL and GnuTLS functions\n"
	"    ./ebhttps -p 181       # sniff PID 181 only\n"
	"    ./ebhttps -u 1000      # sniff only UID 1000\n"
	"    ./ebhttps -c curl      # sniff curl command only\n"
	"    ./ebhttps --no-openssl # don't show OpenSSL calls\n"
	"    ./ebhttps --no-gnutls  # don't show GnuTLS calls\n"
	"    ./ebhttps --no-nss     # don't show NSS calls\n"
	"    ./ebhttps --hexdump    # show data as hex instead of trying to "
	"decode it as UTF-8\n"
	"    ./ebhttps -x           # show process UID and TID\n"
	"    ./ebhttps -l           # show function latency\n"
	"    ./ebhttps -l --handshake  # show SSL handshake latency\n"
	"    ./ebhttps --extra-lib openssl:/path/libssl.so.1.1 # sniff extra "
	"library\n";

struct env {
	pid_t pid;
	int uid;
	bool extra;
	char *comm;
	bool openssl;
	bool gnutls;
	bool nss;
    bool print;
	bool hexdump;
	bool latency;
	bool handshake;
	char *extra_lib;
} env = {
	.uid = INVALID_UID,
	.pid = INVALID_PID,
	.openssl = true,
	.gnutls = true,
	.nss = true,
	.print = false,
	.comm = NULL,
};

#define HEXDUMP_KEY 1000
#define HANDSHAKE_KEY 1002
#define EXTRA_LIB_KEY 1003

static const struct argp_option opts[] = {
	{"pid", 'p', "PID", 0, "Sniff this PID only."},
	{"uid", 'u', "UID", 0, "Sniff this UID only."},
	{"extra", 'x', NULL, 0, "Show extra fields (UID, TID)"},
	{"comm", 'c', "COMMAND", 0, "Sniff only commands matching string."},
	{"no-openssl", 'o', NULL, 0, "Do not show OpenSSL calls."},
	{"no-gnutls", 'g', NULL, 0, "Do not show GnuTLS calls."},
	{"no-nss", 'n', NULL, 0, "Do not show NSS calls."},
	{"hexdump", HEXDUMP_KEY, NULL, 0,
	 "Show data as hexdump instead of trying to decode it as UTF-8"},
	{"latency", 'l', NULL, 0, "Show function latency"},
	{"handshake", HANDSHAKE_KEY, NULL, 0,
	 "Show SSL handshake latency, enabled only if latency option is on."},
	{"print", 'a', NULL, 0, "Print all HTTP header"},
	{"verbose", 'v', NULL, 0, "Verbose debug output"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static bool verbose = false;

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
	switch (key) {
	case 'p':
		env.pid = atoi(arg);
		break;
	case 'u':
		env.uid = atoi(arg);
		break;
	case 'x':
		env.extra = true;
		break;
	case 'c':
		env.comm = strdup(arg);
		break;
	case 'o':
		env.openssl = false;
		break;
	case 'g':
		env.gnutls = false;
		break;
	case 'n':
		env.nss = false;
		break;
	case 'l':
		env.latency = true;
		break;
    case 'a':
		env.print = true;
		break;
	case 'v':
		verbose = true;
		break;
	case HEXDUMP_KEY:
		env.hexdump = true;
		break;
	case HANDSHAKE_KEY:
		env.handshake = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static struct argp argp = {
	opts,
	parse_arg,
	NULL,
	argp_program_doc
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
						   va_list args) {
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static void sig_int(int signo) { 
	exiting = 1;
}

int attach_openssl(struct ebhttps_bpf *skel, const char *lib) {
	ATTACH_UPROBE_CHECKED(skel, lib, SSL_write, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, SSL_write, probe_SSL_write_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, SSL_read, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, SSL_read, probe_SSL_read_exit);

	if (env.latency && env.handshake) {
		ATTACH_UPROBE_CHECKED(skel, lib, SSL_do_handshake,
							probe_SSL_do_handshake_enter);
		ATTACH_URETPROBE_CHECKED(skel, lib, SSL_do_handshake,
								probe_SSL_do_handshake_exit);
	}

	return 0;
}

int attach_gnutls(struct ebhttps_bpf *skel, const char *lib) {
	ATTACH_UPROBE_CHECKED(skel, lib, gnutls_record_send, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, gnutls_record_send, probe_SSL_write_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, gnutls_record_recv, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, gnutls_record_recv, probe_SSL_read_exit);

	return 0;
}

int attach_nss(struct ebhttps_bpf *skel, const char *lib) {
	ATTACH_UPROBE_CHECKED(skel, lib, PR_Write, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, PR_Write, probe_SSL_write_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, PR_Send, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, PR_Send, probe_SSL_write_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, PR_Read, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, PR_Read, probe_SSL_read_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, PR_Recv, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, PR_Recv, probe_SSL_read_exit);

	return 0;
}

/*
 * Find the path of a library using ldconfig.
 */
char *find_library_path(const char *libname) {
	char cmd[128];
	static char path[512];
	FILE *fp;

	// Construct the ldconfig command with grep
	snprintf(cmd, sizeof(cmd), "ldconfig -p | grep %s", libname);

	// Execute the command and read the output
	fp = popen(cmd, "r");
	if (fp == NULL) {
		perror("Failed to run ldconfig");
		return NULL;
	}

	// Read the first line of output which should have the library path
	if (fgets(path, sizeof(path) - 1, fp) != NULL) {
		// Extract the path from the ldconfig output
		char *start = strrchr(path, '>');
		if (start && *(start + 1) == ' ') {
			memmove(path, start + 2, strlen(start + 2) + 1);
			char *end = strchr(path, '\n');
			if (end) {
				*end = '\0';  // Null-terminate the path
			}
			pclose(fp);
			return path;
		}
	}

	pclose(fp);
	return NULL;
}


/*
 * Find the path of a library using ldconfig.
 */
char *find_openssl_library_path(const char *libname) {
	char cmd[128];
	static char path[512];
	FILE *fp;

	// Construct the ldconfig command with grep
	snprintf(cmd, sizeof(cmd), "ldd /usr/bin/openssl | grep %s", libname);

	// Execute the command and read the output
	fp = popen(cmd, "r");
	if (fp == NULL) {
		perror("Failed to run ldconfig");
		return NULL;
	}

	// Read the first line of output which should have the library path
	if (fgets(path, sizeof(path) - 1, fp) != NULL) {
		// Extract the path from the ldconfig output
		char *start = strrchr(path, '>');
		if (start && *(start + 1) == ' ') {
			memmove(path, start + 2, strlen(start + 2) + 1);
			char *end = strchr(path, '\n');
			if (end) {
				*end = '\0';  // Null-terminate the path
			}
            end = strchr(path, ' ');
            if (end) {
				*end = '\0';  // Null-terminate the path
			}
			pclose(fp);
			return path;
		}
	}

	pclose(fp);
	return NULL;
}


void buf_to_hex(const uint8_t *buf, size_t len, char *hex_str) {
    size_t i = 0;

	for (i = 0; i < len; i++) {
		sprintf(hex_str + 2 * i, "%02x", buf[i]);
	}
}

static char g_http_str[16384];
static void set_sa_addr_v4(struct ip *this_iphdr, unsigned short sport, unsigned short dport) {
    sa_src.ss_family = AF_INET;
    ((struct sockaddr_in *)&sa_src)->sin_port    = htons(sport);
    ((struct sockaddr_in *)&sa_src)->sin_addr    = this_iphdr->ip_src;

     sa_dst.ss_family = AF_INET;
    ((struct sockaddr_in *)&sa_dst)->sin_port    = htons(dport);
    ((struct sockaddr_in *)&sa_dst)->sin_addr    = this_iphdr->ip_dst;


}


static void process_waf_request(int len){

    http_waf_msg          	req_msg;
    int                     i,ret,alert = 0;
  
 
    if (memcmp(g_http_str,"GET ",4) == 0 || memcmp(g_http_str,"POST ",5) == 0) {
        
            memset(&req_msg,0,sizeof(http_waf_msg)); 
            req_msg.buf   = g_req_buf;  
            if (env.print)
                printf("%s\n",g_http_str);           
             alert = process_http(g_http_str,len,&req_msg); 
       
                       
             if (1 == alert || 2 == alert)		{
					 log_http_to_file(sa_src,&req_msg,alert,g_http_str,len);				
                  
		     }

             if ( req_msg.ddos == 1) {
                req_msg.ddos = 0;
                ret =  process_cc_ddos(sa_src,&req_msg);
                if(DROP == ret || ALERT == ret)
                {
                    log_http_to_file(sa_src,&req_msg,alert,g_http_str,len);	
                }
            }

      
          
      
        }
	 

}


// Function to print the event from the perf buffer
void print_event(struct probe_SSL_data_t *event, const char *evt) {
	static unsigned long long start =
		0;  // Use static to retain value across function calls
	char buf[MAX_BUF_SIZE + 1] = {0};  // +1 for null terminator
	unsigned int buf_size;

	if (event->len <= MAX_BUF_SIZE) {
		buf_size = event->len;
	} else {
		buf_size = MAX_BUF_SIZE;
	}

	if (event->buf_filled == 1) {
		memcpy(buf, event->buf, buf_size);
	} else {
		buf_size = 0;
	}

	if (env.comm && strcmp(env.comm, event->comm) != 0) {
		return;
	}

    memcpy(g_http_str, event->buf, buf_size);
    g_http_str[buf_size] = 0;
    process_waf_request(buf_size);

    return;

    

	if (start == 0) {
		start = event->timestamp_ns;
	}
	double time_s = (double)(event->timestamp_ns - start) / 1000000000;

	char lat_str[10];
	if (event->delta_ns) {
		snprintf(lat_str, sizeof(lat_str), "%.3f",
				(double)event->delta_ns / 1000000);
	} else {
		strncpy(lat_str, "N/A", sizeof(lat_str));
	}

	char s_mark[] = "----- DATA -----";
	char e_mark[64] = "----- END DATA -----";
	if (buf_size < event->len) {
		snprintf(e_mark, sizeof(e_mark),
				"----- END DATA (TRUNCATED, %d bytes lost) -----",
				event->len - buf_size);
	}

	char *rw_event[] = {
		"READ/RECV",
		"WRITE/SEND",
		"HANDSHAKE"
	};

#define BASE_FMT "%-12s %-18.9f %-16s %-7d %-6d"
#define EXTRA_FMT " %-7d %-7d"
#define LATENCY_FMT " %-7s"

	if (env.extra && env.latency) {
		printf(BASE_FMT EXTRA_FMT LATENCY_FMT, rw_event[event->rw], 
			time_s, event->comm, event->pid,
			event->len, event->uid, event->tid, lat_str);
	} else if (env.extra) {
		printf(BASE_FMT EXTRA_FMT, rw_event[event->rw], time_s, event->comm, event->pid,
			event->len, event->uid, event->tid);
	} else if (env.latency) {
		printf(BASE_FMT LATENCY_FMT, rw_event[event->rw], time_s, event->comm, event->pid,
			event->len, lat_str);
	} else {
		printf(BASE_FMT, rw_event[event->rw], time_s, event->comm, event->pid,
			event->len);
	}

	/*if (buf_size != 0) {
		if (env.hexdump) {
			// 2 characters for each byte + null terminator
			char hex_data[MAX_BUF_SIZE * 2 + 1] = {0};  
			buf_to_hex((uint8_t *)buf, buf_size, hex_data);
			
			printf("\n%s\n", s_mark);
			for (size_t i = 0; i < strlen(hex_data); i += 32) {
				printf("%.32s\n", hex_data + i);
			}
			printf("%s\n\n", e_mark);
		} else {
			printf("\n%s\n%s\n%s\n\n", s_mark, buf, e_mark);
		}
	}*/
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_size) {
	struct probe_SSL_data_t *e = data;
	if (e->is_handshake) {
		print_event(e, "perf_SSL_do_handshake");
	} else {
		print_event(e, "perf_SSL_rw");
	}
}

int main(int argc, char **argv) {
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct ebhttps_bpf *obj = NULL;
	struct perf_buffer *pb = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = ebhttps_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		goto cleanup;
	}

	obj->rodata->targ_uid = env.uid;
	obj->rodata->targ_pid = env.pid == INVALID_PID ? 0 : env.pid;

	err = ebhttps_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

    init_rules();

	if (env.openssl) {
		char *openssl_path = find_library_path("libssl.so");
        if (openssl_path != NULL) {
		   printf("OpenSSL path: %s\n", openssl_path);
           attach_openssl(obj, openssl_path);
        } else {
            openssl_path = find_openssl_library_path("libssl.so");
            if (openssl_path != NULL) {
		        printf("OpenSSL lib path: %s\n", openssl_path);
                attach_openssl(obj, openssl_path);
            } else {
		      attach_openssl(obj, "/lib/x86_64-linux-gnu/libssl.so.3");
            }
        }

      
	}
	if (env.gnutls) {
		char *gnutls_path = find_library_path("libgnutls.so");
        if (gnutls_path != NULL) {
		   printf("GnuTLS path: %s\n", gnutls_path);
		   attach_gnutls(obj, gnutls_path);
        }
	}
	if (env.nss) {
		char *nss_path = find_library_path("libnspr4.so");
        if (nss_path != NULL) {
		   printf("NSS path: %s\n", nss_path);
		   attach_nss(obj, nss_path);
        }
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.perf_SSL_events),
							PERF_BUFFER_PAGES, handle_event, handle_lost_events,
							NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	// Print header
	printf("\nebhttps start ok...sql injection attack example:  curl or wget https://www.baidu.com/?id=123' or 1='1");
	/*if (env.extra) {
		printf(" %-7s %-7s", "UID", "TID");
	}
	if (env.latency) {
		printf(" %-7s", "LAT(ms)");
	}*/
	printf("\n");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	ebhttps_bpf__destroy(obj);
	return err != 0;
}
