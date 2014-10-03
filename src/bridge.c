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
#include <qpid/dispatch/iterator.h>
#include <qpid/dispatch/timer.h>

#define MTU 1500

int tap_open(char *dev);
int tun_open(char *dev);

typedef struct ip_header_t {
    uint8_t  version;
    uint8_t  field1;
    uint16_t field2;
    uint32_t field3;
    union {
        struct {
            uint32_t field4;
            uint32_t v4_src_addr;
            uint32_t v4_dst_addr;
        } v4;
        struct {
            uint16_t v6_src_addr[8];
            uint16_t v6_dst_addr[8];
        } v6;
    };
} ip_header_t;

static const char        *MODULE = "BRIDGE";
static qd_dispatch_t     *dx;
static qd_log_source_t   *log_source = 0;
static qd_user_fd_t      *user_fd;
static int                fd;
static qd_node_t         *node;
static qd_link_t         *sender;
static qd_link_t         *receiver4;
static qd_link_t         *receiver6;
static qd_message_list_t  out_messages;
static qd_message_list_t  in_messages;
static uint64_t           tag = 1;
static sys_mutex_t       *lock;
static qd_timer_t        *timer;

static       char *address4;
static       char *address6;
static const char *vlan = "vlan0";

/*
typedef struct {
    const char      *label;
    struct timespec  ts;
} lq_timeitem;

static lq_timeitem timeItems[10];
static int         timeItemIndex = 0;

static void lq_timestamp_LH(const char *label)
{
    timeItems[timeItemIndex].label = label;
    clock_gettime(CLOCK_REALTIME, &timeItems[timeItemIndex].ts);
    timeItemIndex++;

    if (timeItemIndex == 10) {
        int i;
        timeItemIndex = 0;
        for (i = 0; i < 10; i++)
            printf("%ld:%ld - %s\n", timeItems[i].ts.tv_sec, timeItems[i].ts.tv_nsec, timeItems[i].label);
    }
}
*/

static void timer_handler(void *unused)
{
    qd_timer_schedule(timer, 1000);
}

/**
 * get_dest_addr
 *
 * Given a buffer received from the tunnel interface, extract the destination
 * IP address and generate an AMQP address from the vlan name and the IP address.
 */
static void get_dest_addr(unsigned char *buffer, char *addr, int len)
{
    const ip_header_t *hdr = (const ip_header_t*) buffer;

    if ((hdr->version & 0xf0) == 0x40) {
        uint32_t ip4_addr = ntohl(hdr->v4.v4_dst_addr);
        snprintf(addr, len, "u/%s/%d.%d.%d.%d", vlan,
                 (ip4_addr & 0xFF000000) >> 24,
                 (ip4_addr & 0x00FF0000) >> 16,
                 (ip4_addr & 0x0000FF00) >> 8,
                 (ip4_addr & 0x000000FF));
    } else {
        snprintf(addr, len, "u/%s/%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", vlan,
                 ntohs(hdr->v6.v6_dst_addr[0]),
                 ntohs(hdr->v6.v6_dst_addr[1]),
                 ntohs(hdr->v6.v6_dst_addr[2]),
                 ntohs(hdr->v6.v6_dst_addr[3]),
                 ntohs(hdr->v6.v6_dst_addr[4]),
                 ntohs(hdr->v6.v6_dst_addr[5]),
                 ntohs(hdr->v6.v6_dst_addr[6]),
                 ntohs(hdr->v6.v6_dst_addr[7]));
    }
}


/**
 * user_fd_handler
 *
 * This handler is called when the FD for the tunnel interface is either readable,
 * writable, or both.
 */
static void user_fd_handler(void *context, qd_user_fd_t *ufd)
{
    char              addr_str[200];
    qd_message_t     *msg;
    qd_buffer_t      *buf;
    qd_buffer_list_t  buffers;
    ssize_t           len;

    DEQ_INIT(buffers);

    if (qd_user_fd_is_writeable(ufd)) {
        sys_mutex_lock(lock);
        msg = DEQ_HEAD(in_messages);
        while (msg) {
            //lq_timestamp_LH("Write to Tunnel");
            qd_field_iterator_t *body_iter    = qd_message_field_iterator(msg, QD_FIELD_BODY);
            qd_parsed_field_t   *content      = qd_parse(body_iter);
            qd_field_iterator_t *content_iter = qd_parse_raw(content);
            qd_iovec_t          *iov          = qd_field_iterator_iovec(content_iter);
            qd_parse_free(content);
            qd_field_iterator_free(body_iter);
            if (iov) {
                len = writev(fd, qd_iovec_array(iov), qd_iovec_count(iov));
                qd_iovec_free(iov);
                if (len == -1) {
                    if (errno == EAGAIN || errno == EINTR) {
                        //
                        // FD socket is not accepting writes (it's full).  Activate for write
                        // so we'll come back here when it's again writable.
                        //
                        qd_user_fd_activate_write(user_fd);
                        break;
                    }
                }
            }

            DEQ_REMOVE_HEAD(in_messages);
            qd_message_free(msg);
            qd_log(log_source, QD_LOG_TRACE, "Inbound Datagram: len=%ld", len);
            msg = DEQ_HEAD(in_messages);
        }
        sys_mutex_unlock(lock);
    }

    if (qd_user_fd_is_readable(ufd)) {
        while (1) {
            // TODO - Scatter the read into message buffers
            buf = qd_buffer();
            len = read(fd, qd_buffer_base(buf), MTU);
            if (len == -1) {
                qd_buffer_free(buf);
                if (errno == EAGAIN || errno == EINTR) {
                    qd_user_fd_activate_read(user_fd);
                    return;
                }

                qd_log(log_source, QD_LOG_ERROR, "Error on tunnel fd: %s", strerror(errno));
                qd_server_stop(dx);
                return;
            }

            if (len < 20) {
                qd_buffer_free(buf);
                continue;
            }

            qd_buffer_insert(buf, len);
            DEQ_INSERT_HEAD(buffers, buf);
            get_dest_addr(qd_buffer_base(buf), addr_str, 200);

            //
            // Create an AMQP message with the packet's destination address and
            // the whole packet in the message body.  Enqueue the message on the
            // out_messages queue for transmission.
            //
            msg = qd_message();
            qd_message_compose_1(msg, addr_str, &buffers);
            sys_mutex_lock(lock);
            DEQ_INSERT_TAIL(out_messages, msg);
            //lq_timestamp_LH("Read from Tunnel");
            sys_mutex_unlock(lock);

            //
            // Activate our amqp sender.  This will cause the bridge_writable_handler to be
            // invoked when the amqp socket is willing to accept writes.
            //
            qd_link_activate(sender);

            qd_log(log_source, QD_LOG_TRACE, "Outbound Datagram: dest=%s len=%ld", addr_str, len);
        }
    }

    qd_user_fd_activate_read(user_fd); // FIX THIS!!
}


static void bridge_rx_handler(void *node_context, qd_link_t *link, qd_delivery_t *delivery)
{
    pn_link_t           *pn_link = qd_link_pn(link);
    qd_message_t        *msg;
    int                  valid_message = 0;
    qd_field_iterator_t *iter = 0;

    //
    // Extract the message from the incoming delivery.
    //
    msg = qd_message_receive(delivery);
    if (!msg)
        //
        // The delivery didn't contain the entire message, we'll come through here
        // again when there's more data to receive.
        //
        return;

    //
    // Parse and validate the message up to the message body.
    //
    valid_message = qd_message_check(msg, QD_DEPTH_BODY);
    if (valid_message)
        iter = qd_message_field_iterator(msg, QD_FIELD_BODY);

    //
    // Advance the link and issue flow-control credit.
    //
    pn_link_advance(pn_link);
    pn_link_flow(pn_link, 1);

    sys_mutex_lock(lock);
    if (valid_message) {
        //
        // The message is valid.  If it contains a non-null body, enqueue it on the in_messages
        // queue and activate the tunnel FD for write.
        //
        if (iter) {
            DEQ_INSERT_TAIL(in_messages, msg);
            qd_user_fd_activate_write(user_fd);
            qd_field_iterator_free(iter);
            //lq_timestamp_LH("Received encapsulated PDU");
        }

        qd_delivery_free_LH(delivery, PN_ACCEPTED);
    } else {
        //
        // The message is malformed in some way.  Reject it.
        //
        qd_delivery_free_LH(delivery, PN_REJECTED);
        qd_message_free(msg);
    }

    sys_mutex_unlock(lock);
}


static void bridge_disp_handler(void *node_context, qd_link_t *link, qd_delivery_t *delivery)
{
}


static int bridge_incoming_handler(void *node_context, qd_link_t *link)
{
    return 0;
}


static int bridge_outgoing_handler(void *node_context, qd_link_t *link)
{
    return 0;
}


static int bridge_writable_handler(void *node_context, qd_link_t *link)
{
    uint64_t           dtag;
    pn_link_t         *pn_link = qd_link_pn(link);
    int                link_credit = pn_link_credit(pn_link);
    qd_message_list_t  to_send;
    qd_message_t      *msg;
    size_t             offer;
    int                event_count = 0;
    bool               drain_mode;
    bool               drain_changed = qd_link_drain_changed(link, &drain_mode);

    DEQ_INIT(to_send);

    sys_mutex_lock(lock);
    if (link_credit > 0) {
        dtag = tag;
        msg = DEQ_HEAD(out_messages);
        while (msg) {
            DEQ_REMOVE_HEAD(out_messages);
            DEQ_INSERT_TAIL(to_send, msg);
            //lq_timestamp_LH("Sending encapsulated PDU");
            if (DEQ_SIZE(to_send) == link_credit)
                break;
            msg = DEQ_HEAD(out_messages);
        }
        tag += DEQ_SIZE(to_send);
    }

    offer = DEQ_SIZE(out_messages);
    sys_mutex_unlock(lock);

    msg = DEQ_HEAD(to_send);
    while (msg) {
        DEQ_REMOVE_HEAD(to_send);
        dtag++;
        qd_delivery_t *delivery = qd_delivery(link, pn_dtag((char*) &dtag, 8));
        qd_message_send(msg, link);
        pn_link_advance(pn_link);
        event_count++;
        sys_mutex_lock(lock);
        qd_delivery_free_LH(delivery, 0);
        sys_mutex_unlock(lock);
        qd_message_free(msg);
        msg = DEQ_HEAD(to_send);
    }

    if (offer > 0)
        pn_link_offered(pn_link, offer);
    else {
        pn_link_drained(pn_link);
        if (drain_changed && drain_mode)
            event_count++;
    }

    return event_count;
}


static int bridge_detach_handler(void *node_context, qd_link_t *link, int closed)
{
    return 0;
}


static void bridge_outbound_conn_open_handler(void *type_context, qd_connection_t *conn, void *context)
{
    qd_log(log_source, QD_LOG_INFO, "AMQP Connection Established");

    sender = qd_link(node, conn, QD_OUTGOING, "vlan-sender");

    if (address4) {
        receiver4 = qd_link(node, conn, QD_INCOMING, "vlan-receiver4");
        pn_terminus_set_address(qd_link_source(receiver4), address4);
        pn_terminus_set_address(qd_link_remote_target(receiver4), address4);
        pn_link_open(qd_link_pn(receiver4));
        pn_link_flow(qd_link_pn(receiver4), 40);
    }

    if (address6) {
        receiver6 = qd_link(node, conn, QD_INCOMING, "vlan-receiver6");
        pn_terminus_set_address(qd_link_source(receiver6), address6);
        pn_terminus_set_address(qd_link_remote_target(receiver6), address6);
        pn_link_open(qd_link_pn(receiver6));
        pn_link_flow(qd_link_pn(receiver6), 40);
    }

    pn_link_open(qd_link_pn(sender));
}


static const qd_node_type_t node_descriptor = {"vlan-controller", 0, 0,
                                               bridge_rx_handler,
                                               bridge_disp_handler,
                                               bridge_incoming_handler,
                                               bridge_outgoing_handler,
                                               bridge_writable_handler,
                                               bridge_detach_handler,
                                               0, 0, 0,
                                               bridge_outbound_conn_open_handler
};

//static const char *CONF_VLAN      = "vlan";
//static const char *CONF_VLAN_NAME = "name";
//static const char *CONF_VLAN_IP   = "ip-addr";
//static const char *CONF_VLAN_IF   = "if-name";


int bridge_setup(qd_dispatch_t *_dx)
{
    const char *_ip4 = 0;
    const char *_ip6 = 0;
    const char *_if  = "lanq0";

    const char *env;

    if ((env = getenv("LANQP_VLAN")))
        vlan = env;

    if ((env = getenv("LANQP_IF")))
        _if = env;

    _ip4 = getenv("LANQP_IP");
    _ip6 = getenv("LANQP_IP6");
    if (!_ip4 && !_ip6) {
        printf("Environment variables LANQP_IP abd LANQP_IP6 not set\n");
        exit(1);
    }

    dx = _dx;

    // TODO - Get vlan configuration from the config file

    //    int count = qd_config_item_count(dx, CONF_VLAN);
    //    if (count > 0) {
    //        vlan  = qd_config_item_value_string(dx, CONF_VLAN, 0, CONF_VLAN_NAME);
    //        _ip   = qd_config_item_value_string(dx, CONF_VLAN, 0, CONF_VLAN_IP);
    //        _if   = qd_config_item_value_string(dx, CONF_VLAN, 0, CONF_VLAN_IF);
    //    }

    if (_ip4) {
        address4 = (char*) malloc(strlen(vlan) + strlen(_ip4) + 3);
        strcpy(address4, "u/");
        strcat(address4, vlan);
        strcat(address4, "/");
        strcat(address4, _ip4);
    }

    if (_ip6) {
        address6 = (char*) malloc(strlen(vlan) + strlen(_ip6) + 3);
        strcpy(address6, "u/");
        strcat(address6, vlan);
        strcat(address6, "/");
        strcat(address6, _ip6);
    }

    log_source = qd_log_source(MODULE);

    qd_log(log_source, QD_LOG_INFO, "Creating Endpoint on Interface '%s'", _if);
    if (address4) qd_log(log_source, QD_LOG_INFO, "IPv4 Address: %s", address4);
    if (address6) qd_log(log_source, QD_LOG_INFO, "IPv6 Address: %s", address6);

    char *dev = malloc(10);
    strcpy(dev, _if);
    fd = tun_open(dev);

    if (fd == -1) {
        qd_log(log_source, QD_LOG_ERROR, "Tunnel open failed on device %s: %s", dev, strerror(errno));
        return -1;
    }

    int flags = fcntl(fd, F_GETFL);
    flags |= O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) < 0) {
        qd_log(log_source, QD_LOG_ERROR, "Tunnel failed to set non-blocking: %s", strerror(errno));
        close(fd);
        return -1;
    }

    lock = sys_mutex();

    qd_log(log_source, QD_LOG_INFO, "Tunnel opened: %s", dev);

    DEQ_INIT(out_messages);
    DEQ_INIT(in_messages);

    //
    // Register the FD as a user-fd to be managed by dispatch-server.
    //
    qd_server_set_user_fd_handler(dx, user_fd_handler);
    user_fd = qd_user_fd(dx, fd, 0);
    if (user_fd == 0) {
        qd_log(log_source, QD_LOG_ERROR, "Failed to create qd_user_fd");
        close(fd);
        return -1;
    }
    qd_user_fd_activate_read(user_fd);
    qd_user_fd_activate_write(user_fd);

    //
    // Setup periodic timer
    //
    timer = qd_timer(dx, timer_handler, 0);
    qd_timer_schedule(timer, 0);

    //
    // Register self as a container type and instance.
    //
    qd_container_register_node_type(dx, &node_descriptor);
    node = qd_container_create_node(dx, &node_descriptor, "qnet", 0, QD_DIST_MOVE, QD_LIFE_PERMANENT);

    return 0;
}

