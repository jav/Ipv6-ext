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

static int inet6_ext_create_socket(struct net *net, struct socket *sock, int protocol, int kern);


/* Protocol specific socket structure */
struct inet6_ext_sock {
	struct inet_sock isk;
	/* Add the Protocol implementation specific data members per socket here from here on */
};

struct proto inet6_ext_proto = {
/*	.close = inet6_ext_close,
	.connect = inet6_ext_connect,
	.disconnect = inet6_ext_disconnect,
	.accept = inet6_ext_accept,
	.ioctl = inet6_ext_ioctl,
	.init = inet6_ext_init_sock,
	.shutdown = inet6_ext_shutdown,
	.setsockopt = inet6_ext_setsockopt,
	.getsockopt = inet6_ext_getsockopt,
	.sendmsg = inet6_ext_sendmsg,
	.recvmsg = inet6_ext_recvmsg,
	.unhash = inet6_ext_unhash,
	.get_port = inet6_ext_get_port,
	.enter_memory_pressure = inet6_ext_enter_memory_pressure,
	.sockets_allocated = &sockets_allocated,
	.memory_allocated = &memory_allocated,
	.memory_pressure = &memory_pressure,
	.orphan_count = &orphan_count,
	.sysctl_mem = sysctl_tcp_mem,
	.sysctl_wmem = sysctl_tcp_wmem,
	.sysctl_rmem = sysctl_tcp_rmem,
	.max_header = 0, */
	.obj_size = sizeof(struct inet6_ext_sock),
	.owner = THIS_MODULE,
	.name = "NEW_TCP",
};

static struct proto_ops inet6_ext_proto_ops = {
	.family = PF_INET6,
	.owner = THIS_MODULE,
	.release = inet_release,
/*	.bind = inet6_ext_bind,
	.connect = inet_stream_connect,
	.socketpair = sock_no_socketpair,
	.accept = inet_accept,
	.getname = inet_getname,
	.poll = inet6_ext_poll,
	.ioctl = inet_ioctl,
	.listen = inet6_ext_inet_listen,
	.shutdown = inet_shutdown,
	.setsockopt = sock_common_setsockopt,
	.getsockopt = sock_common_getsockopt,
	.sendmsg = inet_sendmsg,
	.recvmsg = sock_common_recvmsg,
*/
};

struct net_proto_family inet6_ext_net_proto = {
	.family = AF_INET6_EXT,
	.create = inet6_ext_create_socket,
	.owner= THIS_MODULE,
};



static int inet6_ext_create_socket(struct net *net, struct socket *sock,  int protocol, int kern)
{
	printk("%s:%d - %s (net: %p, sock: %p, protocol: %d, kern: %d)\n", __FILE__, __LINE__, __FUNCTION__, net, sock, protocol, kern);
	struct sock *sk;
	int rc;

	if( protocol && protocol != PF_INET6_EXT ) {
		printk("%s:%d - %s () : No support for protocol: %d, (expected %d)\n", __FILE__, __LINE__, __FUNCTION__, protocol, AF_INET6_EXT);
		return -EPROTONOSUPPORT;
	}

	printk("%s:%d - %s () : sk = sk_alloc(net: %p, PF_INET6_EXT: %d, GFP_KERNEL: %d, &inet6_ext_proto: %p);\n",__FILE__, __LINE__, __FUNCTION__,  net, PF_INET6_EXT, GFP_KERNEL, inet6_ext_proto);
	sk = sk_alloc(net, PF_INET6_EXT, GFP_KERNEL, &inet6_ext_proto);
	printk("%s:%d - %s () : sk: %p = sk_alloc(net, PF_INET6_EXT, GFP_KERNEL, &inet6_ext_proto );\n",__FILE__, __LINE__, __FUNCTION__,  sk);
	if (!sk) {
		printk("failed to allocate socket.\n");
		return -ENOMEM;
	}
	
	sock_init_data(sock, sk);
	sk->sk_protocol = 0x0;
	
	sock->ops = &inet6_ext_proto_ops;
	sock->state = SS_UNCONNECTED;
	
        /* Do the protocol specific socket object initialization */
	return 0;
};

static int af_inet6_ext_init(void)
{
	printk("%s:%d - %s ()\n", __FILE__, __LINE__, __FUNCTION__);

        int rc;
	rc = proto_register( &inet6_ext_proto, 1 );
	if (rc) {
		printk("%s:%d - %s () - proto_register( &inet6_ext_proto) returned rc: %d\n", __FILE__, __LINE__, __FUNCTION__, rc);
		goto out;
	}

	rc = sock_register( &inet6_ext_net_proto );
	if (rc) {
		printk("%s:%d - %s () - sock_register( &inet6_ext_net_proto) returned rc: %d\n", __FILE__, __LINE__, __FUNCTION__, rc);
		goto out;
	}

out:
	return rc;
}

static void af_inet6_ext_exit(void)
{
	printk("%s:%d - %s ()\n", __FILE__, __LINE__, __FUNCTION__);

	printk("%s:%d - %s () - sock_unregister( &inet6_ext_net_proto)\n", __FILE__, __LINE__, __FUNCTION__);
	sock_unregister( inet6_ext_net_proto.family);

	printk("%s:%d - %s () - proto_unregister( &inet6_ext_proto)\n", __FILE__, __LINE__, __FUNCTION__);
	proto_unregister( &inet6_ext_proto );

}


module_init(af_inet6_ext_init);
module_exit(af_inet6_ext_exit);
