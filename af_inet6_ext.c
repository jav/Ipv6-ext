#include <linux/module.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/slab.h>

#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/icmpv6.h>
#include <linux/netfilter_ipv6.h>

#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>
#include <net/udplite.h>
#include <net/tcp.h>
#include <net/ipip.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/route.h>
#include <net/transp_v6.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#ifdef CONFIG_IPV6_TUNNEL
#include <net/ip6_tunnel.h>
#endif

#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/mroute6.h>

MODULE_AUTHOR("Javier Ubillos");
MODULE_DESCRIPTION("Extension to IPv6 protocol stack to easily add extensionheaders");
MODULE_LICENSE("GPL");

static int my_create_socket(struct socket *sock, int protocol);


/* Protocol specific socket structure */
struct my_sock {
	struct inet_sock isk;
	/* Add the Protocol implementation specific data members per socket here from here on */
};

struct proto inet6_ext_proto = {
/*	.close = my_close,
	.connect = my_connect,
	.disconnect = my_disconnect,
	.accept = my_accept,
	.ioctl = my_ioctl,
	.init = my_init_sock,
	.shutdown = my_shutdown,
	.setsockopt = my_setsockopt,
	.getsockopt = my_getsockopt,
	.sendmsg = my_sendmsg,
	.recvmsg = my_recvmsg,
	.unhash = my_unhash,
	.get_port = my_get_port,
	.enter_memory_pressure = my_enter_memory_pressure,
	.sockets_allocated = &sockets_allocated,
	.memory_allocated = &memory_allocated,
	.memory_pressure = &memory_pressure,
	.orphan_count = &orphan_count,
	.sysctl_mem = sysctl_tcp_mem,
	.sysctl_wmem = sysctl_tcp_wmem,
	.sysctl_rmem = sysctl_tcp_rmem,
	.max_header = 0, */
	.obj_size = sizeof(struct my_sock),
	.owner = THIS_MODULE,
	.name = "NEW_TCP",
};

static struct proto_ops my_proto_ops = {
	.family = PF_INET6,
	.owner = THIS_MODULE,
	.release = inet_release,
/*	.bind = my_bind,
	.connect = inet_stream_connect,
	.socketpair = sock_no_socketpair,
	.accept = inet_accept,
	.getname = inet_getname,
	.poll = my_poll,
	.ioctl = inet_ioctl,
	.listen = my_inet_listen,
	.shutdown = inet_shutdown,
	.setsockopt = sock_common_setsockopt,
	.getsockopt = sock_common_getsockopt,
	.sendmsg = inet_sendmsg,
	.recvmsg = sock_common_recvmsg,
*/
};

struct net_proto_family my_net_proto = {
	.family = AF_INET6_EXT,
	.create = my_create_socket,
	.owner= THIS_MODULE,
};


static int my_create_socket(struct socket *sock, int protocol)
{
	struct sock *sk;
	int rc;
	sk = sk_alloc(PF_INET6_EXT, GFP_KERNEL, &inet6_ext_proto, 1);
	if (!sk) {
		printk("failed to allocate socket.\n");
		return -ENOMEM;
	}
	
	sock_init_data(sock, sk);
	sk->sk_protocol = 0x0;
	
	sock->ops = &my_proto_ops;
	sock->state = SS_UNCONNECTED;
	
        /* Do the protocol specific socket object initialization */
	return 0;
};

static int af_inet6_ext_init(void)
{
	printk("%s:%d - %s ()\n", __FILE__, __LINE__, __FUNCTION__);

        int rc;
	rc = proto_register( &inet6_ext_proto, 1 );
	if (rc)
		goto out;

	rc = sock_register( &inet6_ext_proto );

out:
	return rc;
}

static void af_inet6_ext_exit(void)
{
	printk("%s:%d - %s ()\n", __FILE__, __LINE__, __FUNCTION__);
	proto_unregister(&inet6_ext_proto);
}


module_init(af_inet6_ext_init);
module_exit(af_inet6_ext_exit);
