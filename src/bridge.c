#include <stdint.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include <errno.h>
#include <nexus/ctools.h>
#include <nexus/log.h>
#include <nexus/server.h>
#include <nexus/container.h>
#include <nexus/message.h>

#define MTU 1500

int tap_open(char *dev);
int tun_open(char *dev);

typedef struct ip_header_t {
    uint8_t  ver_hlen;
    uint8_t  tos;
    uint16_t len;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t hcksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} ip_header_t;

static const char        *MODULE = "BRIDGE";
static nx_user_fd_t      *user_fd;
static int                fd;
static pn_session_t      *sess;
static pn_link_t         *sender;
static pn_link_t         *receiver;
static nx_message_list_t  out_messages;
static nx_message_list_t  in_messages;

static void get_dest_addr(const char *buffer, char *addr, int len, const char *prefix)
{
    const ip_header_t *hdr = (const ip_header_t*) buffer;

    if ((hdr->ver_hlen & 0xf0) == 0x40) {
        uint32_t ip4_addr = ntohl(hdr->dst_addr);
        snprintf(addr, len, "%s.%d.%d.%d.%d", prefix,
                 (ip4_addr & 0xFF000000) >> 24,
                 (ip4_addr & 0x00FF0000) >> 16,
                 (ip4_addr & 0x0000FF00) >> 8,
                 (ip4_addr & 0x000000FF));
    } else {
        addr[0] = '\0';
    }
}


static void user_fd_handler(void *context, nx_user_fd_t *ufd)
{
    char buffer[MTU];
    char addr_str[200];

    // TODO - Discriminate between writable and readable activation
    //        If writable, send IP packets in the bodies of messagse in the in_messages list
    //        If readable, do below

    while (1) {
        // TODO - Scatter the read into message buffers
        ssize_t len = read(fd, buffer, MTU);
        if (len == -1) {
            if (errno == EAGAIN || errno == EINTR) {
                nx_user_fd_activate_read(user_fd);
                return;
            }

            nx_log(MODULE, LOG_ERROR, "Error on tunnel fd: %s", strerror(errno));
            nx_server_stop();
            return;
        }

	if (len < 20)
	  continue;

	get_dest_addr(buffer, addr_str, 200, "vlan");

        // TODO - Build the message headers
        // TODO - Place the headers and buffers into a message and enqueue on the out_messages list
        // TODO - Activate the sender link for transmit

        nx_log(MODULE, LOG_TRACE, "From tunnel: dest=%s len=%ld", addr_str, len);
    }
}


static void bridge_rx_handler(void *node_context, nx_link_t *link, pn_delivery_t *delivery)
{
}


static void bridge_tx_handler(void *node_context, nx_link_t *link, pn_delivery_t *delivery)
{
}


static void bridge_disp_handler(void *node_context, nx_link_t *link, pn_delivery_t *delivery)
{
}


static int bridge_incoming_handler(void *node_context, nx_link_t *link)
{
    return 0;
}


static int bridge_outgoing_handler(void *node_context, nx_link_t *link)
{
    return 0;
}


static int bridge_writable_handler(void *node_context, nx_link_t *link)
{
    return 0;
}


static int bridge_detach_handler(void *node_context, nx_link_t *link, int closed)
{
    return 0;
}


static void bridge_outbound_conn_open_handler(void *type_context, nx_connection_t *conn)
{
    nx_log(MODULE, LOG_INFO, "AMQP Connection Established");

    // TODO - Get the IP address for the interface (see 'man netdevice')
    const char *my_addr = "vlan.10.1.1.1";

    sess = pn_session(nx_connection_get_engine(conn));

    sender   = pn_sender(sess, "vlan-sender");
    receiver = pn_receiver(sess, "vlan-receiver");

    pn_terminus_set_address(pn_link_remote_target(sender), "all");
    pn_terminus_set_address(pn_link_remote_source(receiver), my_addr);

    pn_terminus_set_address(pn_link_source(sender), "all");
    pn_terminus_set_address(pn_link_target(receiver), my_addr);

    pn_connection_open(nx_connection_get_engine(conn));
    pn_session_open(sess);
    pn_link_open(sender);
    pn_link_open(receiver);

    nx_server_activate(conn);
}


static const nx_node_type_t node_descriptor = {"vlan-controller", 0, 0,
                                               bridge_rx_handler,
                                               bridge_tx_handler,
                                               bridge_disp_handler,
                                               bridge_incoming_handler,
                                               bridge_outgoing_handler,
                                               bridge_writable_handler,
                                               bridge_detach_handler,
                                               0, 0, 0,
                                               bridge_outbound_conn_open_handler};


int bridge_setup()
{
    char *dev = malloc(10);
    strcpy(dev, "qnet0");
    fd = tun_open(dev);

    if (fd == -1) {
        nx_log(MODULE, LOG_ERROR, "Tunnel open failed on device %s: %s", dev, strerror(errno));
        return -1;
    }

    int flags = fcntl(fd, F_GETFL);
    flags |= O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) < 0) {
        nx_log(MODULE, LOG_ERROR, "Tunnel failed to set non-blocking: %s", strerror(errno));
        close(fd);
        return -1;
    }

    nx_log(MODULE, LOG_INFO, "Tunnel opened: %s", dev);

    DEQ_INIT(out_messages);
    DEQ_INIT(in_messages);

    //
    // Register the FD as a user-fd to be managed by nexus-server.
    //
    nx_server_set_user_fd_handler(user_fd_handler);
    user_fd = nx_user_fd(fd, 0);
    if (user_fd == 0) {
        nx_log(MODULE, LOG_ERROR, "Failed to create nx_user_fd");
        close(fd);
        return -1;
    }
    nx_user_fd_activate_read(user_fd);

    //
    // Register self as a container type and instance.
    //
    nx_container_register_node_type(&node_descriptor);
    nx_container_set_default_node_type(&node_descriptor, 0, NX_DIST_MOVE);

    //
    // Establish an outgoing connection to the server.
    //
    static nx_server_config_t client_config;
    client_config.host            = "0.0.0.0";
    client_config.port            = "5672";
    client_config.sasl_mechanisms = "ANONYMOUS";
    client_config.ssl_enabled     = 0;
    nx_server_connect(&client_config, 0);

    return 0;
}

