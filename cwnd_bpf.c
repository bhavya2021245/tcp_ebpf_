include <linux/bpf.h>

#include <linux/socket.h>

#include <linux/types.h>

#include <bpf/bpf_helpers.h>

#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <bpf/bpf_endian.h>

#define DEBUG 1



SEC("sockops")

int bpf_iw(struct bpf_sock_ops *skops)

{

        int bufsize = 1500000;

        int rwnd_init = 40;

        struct in_addr addr;

        int iw = 40;

        int rv = 0;

        int op;

        addr.s_addr=skops->remote_ip4;
        op = (int) skops->op;

        if (op != 4 && op != 5)

                return 0;





#ifdef DEBUG

        bpf_printk("BPF command: %d\n", op);

#endif



        /* Usually there would be a check to insure the hosts are far

         * from each other so it makes sense to increase buffer sizes

         */



        switch (op) {

        case BPF_SOCK_OPS_RWND_INIT:

                rv = rwnd_init;

                break;

        case BPF_SOCK_OPS_TCP_CONNECT_CB:

                /* Set sndbuf and rcvbuf of active connections */
                rv = bpf_setsockopt(skops, SOL_SOCKET, SO_SNDBUF, &bufsize,

                                    sizeof(bufsize));

                rv += bpf_setsockopt(skops, SOL_SOCKET, SO_RCVBUF,

                                     &bufsize, sizeof(bufsize));

                break;

        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:

                rv = bpf_setsockopt(skops, SOL_TCP, TCP_BPF_IW, &iw,

                                    sizeof(iw));

                bpf_printk("IP:%pI4",&addr.s_addr);

                bpf_printk("Initial congestion window%d",iw);

                break;



        default:

                rv = -1;

        }

#ifdef DEBUG

        bpf_printk("Returning %d\n", rv);

#endif

        skops->reply = rv;

        return 1;

}

char _license[] SEC("license") = "GPL";






