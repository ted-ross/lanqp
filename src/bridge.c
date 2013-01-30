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
#include <qpid/nexus/ctools.h>
#include <qpid/nexus/log.h>
#include <qpid/nexus/server.h>
#include <qpid/nexus/user_fd.h>
#include <qpid/nexus/container.h>
#include <qpid/nexus/message.h>
#include <qpid/nexus/threading.h>

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
static nx_node_t         *node;
static nx_link_t         *sender;
static nx_link_t         *receiver;
static nx_message_list_t  out_messages;
static nx_message_list_t  in_messages;
static uint64_t           tag = 1;
static sys_mutex_t       *lock;

static char *host;
static char *port;
static char *iface;
static char *address;
static char *vlan;

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


static void user_fd_handler(void *context, nx_user_fd_t *ufd)
{
    char          addr_str[200];
    nx_message_t *msg;
    nx_buffer_t  *buf;
    ssize_t       len;

    if (nx_user_fd_is_writeable(ufd)) {
        sys_mutex_lock(lock);
        msg = DEQ_HEAD(in_messages);
        while (msg) {
            len = write(fd, nx_buffer_base(msg->body.buffer) + msg->body.offset, msg->body.length); // TODO - Gather
            if (len == -1) {
                if (errno == EAGAIN || errno == EINTR) {
                    nx_user_fd_activate_write(user_fd);
                    break;
                }
            }

            DEQ_REMOVE_HEAD(in_messages);
            nx_free_message(msg);
            nx_log(MODULE, LOG_TRACE, "Inbound Datagram: len=%ld", len);
            msg = DEQ_HEAD(in_messages);
        }
        sys_mutex_unlock(lock);
    }

    if (nx_user_fd_is_readable(ufd)) {
        while (1) {
            // TODO - Scatter the read into message buffers
            buf = nx_allocate_buffer();
            len = read(fd, nx_buffer_base(buf), MTU);
            if (len == -1) {
                nx_free_buffer(buf);
                if (errno == EAGAIN || errno == EINTR) {
                    nx_user_fd_activate_read(user_fd);
                    return;
                }

                nx_log(MODULE, LOG_ERROR, "Error on tunnel fd: %s", strerror(errno));
                nx_server_stop();
                return;
            }

            if (len < 20) {
                nx_free_buffer(buf);
                continue;
            }

            nx_buffer_insert(buf, len);
            get_dest_addr(nx_buffer_base(buf), addr_str, 200);

            msg = nx_allocate_message();
            nx_message_compose_1(msg, addr_str, buf);
            sys_mutex_lock(lock);
            DEQ_INSERT_TAIL(out_messages, msg);
            sys_mutex_unlock(lock);

            nx_link_activate(sender);

            nx_log(MODULE, LOG_TRACE, "Outbound Datagram: dest=%s len=%ld", addr_str, len);
        }
    }

    nx_user_fd_activate_read(user_fd); // FIX THIS!!
}


static void bridge_rx_handler(void *node_context, nx_link_t *link, pn_delivery_t *delivery)
{
    pn_link_t    *pn_link = pn_delivery_link(delivery);
    nx_message_t *msg;
    int           valid_message = 0;

    msg = nx_message_receive(delivery);
    if (!msg)
        return;

    valid_message = nx_message_check(msg, NX_DEPTH_BODY);

    pn_link_advance(pn_link);
    pn_link_flow(pn_link, 1);

    if (valid_message) {
        nx_field_iterator_t *iter = nx_message_body(msg);
        if (iter) {
            sys_mutex_lock(lock);
            DEQ_INSERT_TAIL(in_messages, msg);
            sys_mutex_unlock(lock);
            nx_user_fd_activate_write(user_fd);
            nx_field_iterator_free(iter);
        }
    } else
        pn_delivery_update(delivery, PN_REJECTED);

    pn_delivery_settle(delivery);
}


static void bridge_tx_handler(void *node_context, nx_link_t *link, pn_delivery_t *delivery)
{
    pn_link_t    *pn_link = pn_delivery_link(delivery);
    nx_message_t *msg;
    nx_buffer_t  *buf;
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

    buf = DEQ_HEAD(msg->buffers);
    while (buf) {
        DEQ_REMOVE_HEAD(msg->buffers);
        pn_link_send(pn_link, (char*) nx_buffer_base(buf), nx_buffer_size(buf));
        nx_free_buffer(buf);
        buf = DEQ_HEAD(msg->buffers);
    }
    nx_free_message(msg);
    pn_delivery_settle(delivery);
    pn_link_advance(pn_link);
    pn_link_offered(pn_link, size);
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
    int        grant_delivery = 0;
    uint64_t   dtag;
    pn_link_t *pn_link = nx_link_pn(link);

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


static int bridge_detach_handler(void *node_context, nx_link_t *link, int closed)
{
    return 0;
}


static void bridge_outbound_conn_open_handler(void *type_context, nx_connection_t *conn)
{
    nx_log(MODULE, LOG_INFO, "AMQP Connection Established");

    // TODO - Get the IP address for the interface (see 'man netdevice')

    sender   = nx_link(node, conn, NX_OUTGOING, "vlan-sender");
    receiver = nx_link(node, conn, NX_INCOMING, "vlan-receiver");

    pn_terminus_set_address(nx_link_remote_target(sender), "all");
    pn_terminus_set_address(nx_link_remote_source(receiver), address);

    pn_terminus_set_address(nx_link_source(sender), "all");
    pn_terminus_set_address(nx_link_target(receiver), address);

    pn_link_open(nx_link_pn(sender));
    pn_link_open(nx_link_pn(receiver));
    pn_link_flow(nx_link_pn(receiver), 10);
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


int bridge_setup(char *_host, char *_port, char *_iface, char *_vlan, char *_ip)
{
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

    lock = sys_mutex();

    nx_log(MODULE, LOG_INFO, "Tunnel opened: %s", dev);

    static nx_allocator_config_t my_config;

    memcpy(&my_config, nx_allocator_default_config(), sizeof(nx_allocator_config_t));
    my_config.buffer_size = 1800;

    nx_allocator_initialize(&my_config);

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
    nx_user_fd_activate_write(user_fd);

    //
    // Register self as a container type and instance.
    //
    nx_container_register_node_type(&node_descriptor);
    node = nx_container_create_node(&node_descriptor, "qnet", 0, NX_DIST_MOVE, NX_LIFE_PERMANENT);

    //
    // Establish an outgoing connection to the server.
    //
    static nx_server_config_t client_config;
    client_config.host            = host;
    client_config.port            = port;
    client_config.sasl_mechanisms = "ANONYMOUS";
    client_config.ssl_enabled     = 0;
    nx_server_connect(&client_config, 0);

    return 0;
}

