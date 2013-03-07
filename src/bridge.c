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
#include "bridge.h"

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
static dx_dispatch_t     *dx;
static dx_user_fd_t      *user_fd;
static int                fd;
static dx_node_t         *node;
static dx_link_t         *sender;
static dx_link_t         *receiver;
static dx_message_list_t  out_messages;
static dx_message_list_t  in_messages;
static uint64_t           tag = 1;
static sys_mutex_t       *lock;

static char *host;
static char *port;
static char *iface;
static char *address;
static char *vlan;

/**
 * get_dest_addr
 *
 * Given a buffer received from the tunnel interface, extract the destination
 * IP address and generate an AMQP address from the vlan name and the IP address.
 */
static void get_dest_addr(unsigned char *buffer, char *addr, int len)
{
    const ip_header_t *hdr = (const ip_header_t*) buffer;

    if ((hdr->ver_hlen & 0xf0) == 0x40) {
        uint32_t ip4_addr = ntohl(hdr->dst_addr);
        snprintf(addr, len, "%s.%d.%d.%d.%d", vlan,
                 (ip4_addr & 0xFF000000) >> 24,
                 (ip4_addr & 0x00FF0000) >> 16,
                 (ip4_addr & 0x0000FF00) >> 8,
                 (ip4_addr & 0x000000FF));
    } else {
        // TODO - Generate an address for an IPv6 destination
        addr[0] = '\0';
    }
}


/**
 * user_fd_handler
 *
 * This handler is called when the FD for the tunnel interface is either readable,
 * writable, or both.
 */
static void user_fd_handler(void *context, dx_user_fd_t *ufd)
{
    char              addr_str[200];
    dx_message_t     *msg;
    dx_buffer_t      *buf;
    dx_buffer_list_t  buffers;
    ssize_t           len;

    DEQ_INIT(buffers);

    if (dx_user_fd_is_writeable(ufd)) {
        sys_mutex_lock(lock);
        msg = DEQ_HEAD(in_messages);
        while (msg) {
            dx_iovec_t *iov = dx_message_field_iovec(msg, DX_FIELD_BODY);
            if (iov) {
                len = writev(fd, dx_iovec_array(iov), dx_iovec_count(iov));
                dx_iovec_free(iov);
                if (len == -1) {
                    if (errno == EAGAIN || errno == EINTR) {
                        //
                        // FD socked is not accepting writes (it's full).  Activate for write
                        // so we'll come back here when it's again writable.
                        //
                        dx_user_fd_activate_write(user_fd);
                        break;
                    }
                }
            }

            DEQ_REMOVE_HEAD(in_messages);
            dx_free_message(msg);
            dx_log(MODULE, LOG_TRACE, "Inbound Datagram: len=%ld", len);
            msg = DEQ_HEAD(in_messages);
        }
        sys_mutex_unlock(lock);
    }

    if (dx_user_fd_is_readable(ufd)) {
        while (1) {
            // TODO - Scatter the read into message buffers
            buf = dx_allocate_buffer();
            len = read(fd, dx_buffer_base(buf), MTU);
            if (len == -1) {
                dx_free_buffer(buf);
                if (errno == EAGAIN || errno == EINTR) {
                    dx_user_fd_activate_read(user_fd);
                    return;
                }

                dx_log(MODULE, LOG_ERROR, "Error on tunnel fd: %s", strerror(errno));
                dx_server_stop(dx);
                return;
            }

            if (len < 20) {
                dx_free_buffer(buf);
                continue;
            }

            dx_buffer_insert(buf, len);
            DEQ_INSERT_HEAD(buffers, buf);
            get_dest_addr(dx_buffer_base(buf), addr_str, 200);

            //
            // Create an AMQP message with the packet's destination address and
            // the whole packet in the message body.  Enqueue the message on the
            // out_messages queue for transmission.
            //
            msg = dx_allocate_message();
            dx_message_compose_1(msg, addr_str, &buffers);
            sys_mutex_lock(lock);
            DEQ_INSERT_TAIL(out_messages, msg);
            sys_mutex_unlock(lock);

            //
            // Activate our amqp sender.  This will cause the bridge_writable_handler to be
            // invoked when the amqp socket is willing to accept writes.
            //
            dx_link_activate(sender);

            dx_log(MODULE, LOG_TRACE, "Outbound Datagram: dest=%s len=%ld", addr_str, len);
        }
    }

    dx_user_fd_activate_read(user_fd); // FIX THIS!!
}


static void bridge_rx_handler(void *node_context, dx_link_t *link, pn_delivery_t *delivery)
{
    pn_link_t    *pn_link = pn_delivery_link(delivery);
    dx_message_t *msg;
    int           valid_message = 0;

    //
    // Extract the message from the incoming delivery.
    //
    msg = dx_message_receive(delivery);
    if (!msg)
        //
        // The delivery didn't contain the entire message, we'll come through here
        // again when there's more data to receive.
        //
        return;

    //
    // Parse and validate the message up to the message body.
    //
    valid_message = dx_message_check(msg, DX_DEPTH_BODY);

    //
    // Advance the link and issue flow-control credit.
    //
    pn_link_advance(pn_link);
    pn_link_flow(pn_link, 1);

    if (valid_message) {
        //
        // The message is valid.  If it contains a non-null body, enqueue it on the in_messages
        // queue and activate the tunnel FD for write.
        //
        dx_field_iterator_t *iter = dx_message_field_iterator(msg, DX_FIELD_BODY);
        if (iter) {
            sys_mutex_lock(lock);
            DEQ_INSERT_TAIL(in_messages, msg);
            sys_mutex_unlock(lock);
            dx_user_fd_activate_write(user_fd);
            dx_field_iterator_free(iter);
        }
    } else {
        //
        // The message is malformed in some way.  Reject it.
        //
        pn_delivery_update(delivery, PN_REJECTED);
        dx_free_message(msg);
    }

    //
    // No matter what happened with the message, settle the delivery.
    //
    pn_delivery_settle(delivery);
}


static void bridge_tx_handler(void *node_context, dx_link_t *link, pn_delivery_t *delivery)
{
    pn_link_t    *pn_link = pn_delivery_link(delivery);
    dx_message_t *msg;
    size_t        size;

    sys_mutex_lock(lock);
    msg = DEQ_HEAD(out_messages);
    if (!msg) {
        sys_mutex_unlock(lock);
        return;
    }

    DEQ_REMOVE_HEAD(out_messages);
    size = DEQ_SIZE(out_messages);
    sys_mutex_unlock(lock);

    dx_message_send(msg, pn_link);

    dx_free_message(msg);
    pn_delivery_settle(delivery);
    pn_link_advance(pn_link);
    pn_link_offered(pn_link, size);
}


static void bridge_disp_handler(void *node_context, dx_link_t *link, pn_delivery_t *delivery)
{
}


static int bridge_incoming_handler(void *node_context, dx_link_t *link)
{
    return 0;
}


static int bridge_outgoing_handler(void *node_context, dx_link_t *link)
{
    return 0;
}


static int bridge_writable_handler(void *node_context, dx_link_t *link)
{
    int        grant_delivery = 0;
    uint64_t   dtag;
    pn_link_t *pn_link = dx_link_pn(link);

    sys_mutex_lock(lock);
    if (DEQ_SIZE(out_messages) > 0) {
        grant_delivery = 1;
        dtag = tag++;
    }
    sys_mutex_unlock(lock);

    if (grant_delivery) {
        pn_delivery(pn_link, pn_dtag((char*) &dtag, 8));
        pn_delivery_t *delivery = pn_link_current(pn_link);
        if (delivery) {
            bridge_tx_handler(node_context, link, delivery);
            return 1;
        }
    }

    return 0;
}


static int bridge_detach_handler(void *node_context, dx_link_t *link, int closed)
{
    return 0;
}


static void bridge_outbound_conn_open_handler(void *type_context, dx_connection_t *conn)
{
    dx_log(MODULE, LOG_INFO, "AMQP Connection Established");

    // TODO - Get the IP address for the interface (see 'man netdevice')

    sender   = dx_link(node, conn, DX_OUTGOING, "vlan-sender");
    receiver = dx_link(node, conn, DX_INCOMING, "vlan-receiver");

    pn_terminus_set_address(dx_link_remote_target(sender), "all");
    pn_terminus_set_address(dx_link_remote_source(receiver), address);

    pn_terminus_set_address(dx_link_source(sender), "all");
    pn_terminus_set_address(dx_link_target(receiver), address);

    pn_link_open(dx_link_pn(sender));
    pn_link_open(dx_link_pn(receiver));
    pn_link_flow(dx_link_pn(receiver), 10);
}


static const dx_node_type_t node_descriptor = {"vlan-controller", 0, 0,
                                               bridge_rx_handler,
                                               bridge_tx_handler,
                                               bridge_disp_handler,
                                               bridge_incoming_handler,
                                               bridge_outgoing_handler,
                                               bridge_writable_handler,
                                               bridge_detach_handler,
                                               0, 0, 0,
                                               bridge_outbound_conn_open_handler};


int bridge_setup(dx_dispatch_t *_dx, char *_host, char *_port, char *_iface, char *_vlan, char *_ip)
{
    dx = _dx;
    host  = _host;
    port  = _port;
    iface = _iface;
    vlan  = _vlan;

    address = (char*) malloc(strlen(_vlan) + strlen(_ip) + 1);
    strcpy(address, _vlan);
    strcat(address, ".");
    strcat(address, _ip);

    char *dev = malloc(10);
    strcpy(dev, iface);
    fd = tun_open(dev);

    if (fd == -1) {
        dx_log(MODULE, LOG_ERROR, "Tunnel open failed on device %s: %s", dev, strerror(errno));
        return -1;
    }

    int flags = fcntl(fd, F_GETFL);
    flags |= O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) < 0) {
        dx_log(MODULE, LOG_ERROR, "Tunnel failed to set non-blocking: %s", strerror(errno));
        close(fd);
        return -1;
    }

    lock = sys_mutex();

    dx_log(MODULE, LOG_INFO, "Tunnel opened: %s", dev);

    DEQ_INIT(out_messages);
    DEQ_INIT(in_messages);

    //
    // Register the FD as a user-fd to be managed by dispatch-server.
    //
    dx_server_set_user_fd_handler(dx, user_fd_handler);
    user_fd = dx_user_fd(dx, fd, 0);
    if (user_fd == 0) {
        dx_log(MODULE, LOG_ERROR, "Failed to create dx_user_fd");
        close(fd);
        return -1;
    }
    dx_user_fd_activate_read(user_fd);
    dx_user_fd_activate_write(user_fd);

    //
    // Register self as a container type and instance.
    //
    dx_container_register_node_type(dx, &node_descriptor);
    node = dx_container_create_node(dx, &node_descriptor, "qnet", 0, DX_DIST_MOVE, DX_LIFE_PERMANENT);

    //
    // Establish an outgoing connection to the server.
    //
    static dx_server_config_t client_config;
    client_config.host            = host;
    client_config.port            = port;
    client_config.sasl_mechanisms = "ANONYMOUS";
    client_config.ssl_enabled     = 0;
    dx_server_connect(dx, &client_config, 0);

    return 0;
}

