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

int inet6_ext_release(struct socket *sock);
static int inet6_ext_create(struct net *net, struct socket *sock, int protocol, int kern);
int inet6_ext_bind( struct socket *sock, struct sockaddr *myaddr, int sockaddr_len);

/* Protocol specific socket structure */
struct inet6_ext_sock {
	struct sock sk;
	struct socket *ipv6_sock;
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
	.name = "IPV6_EXT",
};

static struct proto_ops inet6_ext_proto_ops = {
        .family            = PF_INET6,
        .owner             = THIS_MODULE,
        .release           = inet6_ext_release,
        .bind              = inet6_ext_bind,
        .connect           = inet_stream_connect,       /* ok           */
        .socketpair        = sock_no_socketpair,        /* a do nothing */
        .accept            = inet_accept,               /* ok           */
        .getname           = inet6_getname,
        .poll              = tcp_poll,                  /* ok           */
        .ioctl             = inet6_ioctl,               /* must change  */
        .listen            = inet_listen,               /* ok           */
        .shutdown          = inet_shutdown,             /* ok           */
        .setsockopt        = sock_common_setsockopt,    /* ok           */
        .getsockopt        = sock_common_getsockopt,    /* ok           */
        .sendmsg           = inet_sendmsg,              /* ok           */
        .recvmsg           = inet_recvmsg,              /* ok           */
        .mmap              = sock_no_mmap,
        .sendpage          = inet_sendpage,
        .splice_read       = tcp_splice_read,

};

struct net_proto_family inet6_ext_net_proto = {
	.family = AF_INET6_EXT,
	.create = inet6_ext_create,
	.owner= THIS_MODULE,
};

int inet6_ext_release(struct socket *sock){
	printk("%s:%d - %s (sock: %p)\n", __FILE__, __LINE__, __FUNCTION__, sock);
		struct inet6_ext_sock *sk_inet6_ext = (struct inet6_ext_sock *) sock;
	if( NULL == sk_inet6_ext){
	  	printk("%s:%d - %s () sk_inet_ext is: %p)\n", __FILE__, __LINE__, __FUNCTION__, sk_inet6_ext);
		return -1;
	}
	if( NULL == sk_inet6_ext->ipv6_sock){
	  	printk("%s:%d - %s () sk_inet_ext->ipv6_sock is: %p)\n", __FILE__, __LINE__, __FUNCTION__, sk_inet6_ext->ipv6_sock);
		return -2;
	}
	if( NULL == sk_inet6_ext->ipv6_sock->ops){
	  	printk("%s:%d - %s () sk_inet_ext->ipv6_sock->ops is: %p)\n", __FILE__, __LINE__, __FUNCTION__, sk_inet6_ext->ipv6_sock->ops);
		return -3;
	}
	if( NULL == sk_inet6_ext->ipv6_sock->ops->bind){
	  	printk("%s:%d - %s () sk_inet_ext->ipv6_sock->ops->bind is: %p)\n", __FILE__, __LINE__, __FUNCTION__, sk_inet6_ext->ipv6_sock->ops->bind);
		return -4;
	}
	return sk_inet6_ext->ipv6_sock->ops->release( sock );
}

int inet6_ext_bind( struct socket *sock, struct sockaddr *myaddr, int sockaddr_len) 
{
	printk("%s:%d - %s (sock: %p, myaddr: %p, sockaddr_len: %d)\n", __FILE__, __LINE__, __FUNCTION__, sock, myaddr, sockaddr_len);
	struct inet6_ext_sock *sk_inet6_ext = (struct inet6_ext_sock *) sock;
	if( NULL == sk_inet6_ext){
	  	printk("%s:%d - %s () sk_inet_ext is: %p)\n", __FILE__, __LINE__, __FUNCTION__, sk_inet6_ext);
		return -1;
	}
	if( NULL == sk_inet6_ext->ipv6_sock){
	  	printk("%s:%d - %s () sk_inet_ext->ipv6_sock is: %p)\n", __FILE__, __LINE__, __FUNCTION__, sk_inet6_ext->ipv6_sock);
		return -2;
	}
	if( NULL == sk_inet6_ext->ipv6_sock->ops){
	  	printk("%s:%d - %s () sk_inet_ext->ipv6_sock->ops is: %p)\n", __FILE__, __LINE__, __FUNCTION__, sk_inet6_ext->ipv6_sock->ops);
		return -3;
	}
	if( NULL == sk_inet6_ext->ipv6_sock->ops->bind){
	  	printk("%s:%d - %s () sk_inet_ext->ipv6_sock->ops->bind is: %p)\n", __FILE__, __LINE__, __FUNCTION__, sk_inet6_ext->ipv6_sock->ops->bind);
		return -4;
	}
	return sk_inet6_ext->ipv6_sock->ops->bind( sock, myaddr, sockaddr_len );
}

static struct sock *ipv6_ext_alloc_stream_socket(struct net *net, struct socket *sock)
{
	printk("%s:%d - %s (net: %p, sock: %p)\n", __FILE__, __LINE__, __FUNCTION__, net, sock);
	int i = 0;
	struct sock *sk = sk_alloc(net, PF_INET6_EXT, GFP_ATOMIC, &inet6_ext_proto);

	printk("%s:%d - %s (): sk_alloc(): sk: %p\n", __FILE__, __LINE__, __FUNCTION__, sk);

	struct inet6_ext_sock *sk_inet6_ext;

	if (!sk) {
		printk("%s:%d - %s (): sk is null -> goto out; \n", __FILE__, __LINE__, __FUNCTION__);
		goto out;
	}

	 
	sock_init_data(sock, sk); // Init sk struct and set sk->sk_socket = sock
	sock->ops = &inet6_ext_proto_ops;
	sock->state = SS_UNCONNECTED;

	sk_inet6_ext = (struct inet6_ext_sock *)sk;
    
	sock_create_kern(PF_INET6, SOCK_STREAM, IPPROTO_IP, &sk_inet6_ext->ipv6_sock);
	printk("%s:%d - %s (): sock->inet6_sock: %p)\n", __FILE__, __LINE__, __FUNCTION__, sk_inet6_ext->ipv6_sock);

out:
	return sk;
}

static int inet6_ext_create(struct net *net, struct socket *sock,  int protocol, int kern)
{
	printk("%s:%d - %s (net: %p, sock: %p, protocol: %d, kern: %d)\n", __FILE__, __LINE__, __FUNCTION__, net, sock, protocol, kern);
	struct sock *sk = 0;
	int rc;

	if( protocol && protocol != IPPROTO_TCP ) {
		printk("%s:%d - %s () : No support for protocol: %d, (expected %d)\n", __FILE__, __LINE__, __FUNCTION__, protocol, AF_INET6_EXT);
		return -EPROTONOSUPPORT;
	}

	printk("%s:%d - %s () : sock->type %d\n", __FILE__, __LINE__, __FUNCTION__, sock->type);
	switch (sock->type) {
	case SOCK_STREAM:
		rc = -ENOMEM;
		if ( sk = ipv6_ext_alloc_stream_socket(net, sock) )
			rc = 0;
		break;
	case SOCK_DGRAM:
		rc = -EPROTONOSUPPORT;
		//rc = -ENOMEM;
		/* Not yet supported
		   if ((sk = name_alloc_dgram_socket(net, sock)))
		   rc = 0; */
		break;
	default:
		rc = -EPROTONOSUPPORT;
	}

	if (!sk) {
		printk("failed to allocate socket.\n");
		return -ENOMEM;
	}
	
	return rc;
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
