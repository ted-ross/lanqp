/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

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
#include "netns.h"
#include <qpid/dispatch/iterator.h>
#include <qpid/dispatch/timer.h>
#include <qpid/dispatch/ctools.h>

#define MTU 1500

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

typedef struct tunnel_t {
    DEQ_LINKS(struct tunnel_t);
    const char        *name;
    const char        *ns_pid;
    const char        *vlan;
    const char        *ip_addr;
    const char        *ip6_addr;
    int                fd;
    qd_user_fd_t      *ufd;
    qd_link_t         *ip_link;
    qd_link_t         *ip6_link;
    qd_message_list_t  in_messages;
} tunnel_t;

DEQ_DECLARE(tunnel_t, tunnel_list_t);


static const char        *MODULE = "BRIDGE";
static qd_dispatch_t     *dx;
static qd_log_source_t   *log_source = 0;
static qd_node_t         *node;
static qd_link_t         *sender;
static qd_message_list_t  out_messages;
static uint64_t           tag = 1;
static sys_mutex_t       *lock;
static qd_timer_t        *timer;
static tunnel_list_t      tunnels;

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

static void ip6_segment(char *out, const uint16_t *addr, int idx)
{
    uint16_t seg = ntohs(addr[idx]);

    *out = '\0';

    if (idx == 0) {
        if (seg == 0)
            strcpy(":", out);
        else
            sprintf(out, "%x:", seg);
    } else {
        if (seg == 0 && idx == 7)
            strcpy(":", out);
        else if (seg > 0) {
            uint16_t prev = ntohs(addr[idx - 1]);
            if (prev == 0)
                sprintf(out, ":%x%c", seg, idx < 7 ? ':' : '\0');
            else
                sprintf(out, "%x:", seg);
        }
    }
}

/**
 * get_dest_addr
 *
 * Given a buffer received from the tunnel interface, extract the destination
 * IP address and generate an AMQP address from the vlan name and the IP address.
 */
static void get_dest_addr(const unsigned char *buffer, const char *vlan, char *addr, int len)
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
        char seg[8][8];
        int  idx;

        for (idx = 0; idx < 8; idx++)
            ip6_segment(seg[idx], hdr->v6.v6_dst_addr, idx);

        snprintf(addr, len, "u/%s/%s%s%s%s%s%s%s%s", vlan,
                 seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7]);
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
    tunnel_t         *tunnel = (tunnel_t*) context;

    DEQ_INIT(buffers);

    if (qd_user_fd_is_writeable(ufd)) {
        sys_mutex_lock(lock);
        msg = DEQ_HEAD(tunnel->in_messages);
        while (msg) {
            //lq_timestamp_LH("Write to Tunnel");
            qd_field_iterator_t *body_iter    = qd_message_field_iterator(msg, QD_FIELD_BODY);
            qd_parsed_field_t   *content      = qd_parse(body_iter);
            qd_field_iterator_t *content_iter = qd_parse_raw(content);
            qd_iovec_t          *iov          = qd_field_iterator_iovec(content_iter);
            qd_parse_free(content);
            qd_field_iterator_free(body_iter);
            if (iov) {
                len = writev(tunnel->fd, qd_iovec_array(iov), qd_iovec_count(iov));
                qd_iovec_free(iov);
                if (len == -1) {
                    if (errno == EAGAIN || errno == EINTR) {
                        //
                        // FD socket is not accepting writes (it's full).  Activate for write
                        // so we'll come back here when it's again writable.
                        //
                        qd_user_fd_activate_write(ufd);
                        break;
                    }
                }
            }

            DEQ_REMOVE_HEAD(tunnel->in_messages);
            qd_message_free(msg);
            qd_log(log_source, QD_LOG_TRACE, "Inbound Datagram: len=%ld", len);
            msg = DEQ_HEAD(tunnel->in_messages);
        }
        sys_mutex_unlock(lock);
    }

    if (qd_user_fd_is_readable(ufd)) {
        while (1) {
            // TODO - Scatter the read into message buffers
            buf = qd_buffer();
            len = read(tunnel->fd, qd_buffer_base(buf), MTU);
            if (len == -1) {
                qd_buffer_free(buf);
                if (errno == EAGAIN || errno == EINTR) {
                    qd_user_fd_activate_read(ufd);
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
            get_dest_addr(qd_buffer_base(buf), tunnel->vlan, addr_str, 200);

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

    qd_user_fd_activate_read(ufd); // FIX THIS!!
}


static void bridge_rx_handler(void *node_context, qd_link_t *link, qd_delivery_t *delivery)
{
    pn_link_t           *pn_link = qd_link_pn(link);
    qd_message_t        *msg;
    int                  valid_message = 0;
    qd_field_iterator_t *iter = 0;
    tunnel_t            *tunnel = (tunnel_t*) qd_link_get_context(link);

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
            DEQ_INSERT_TAIL(tunnel->in_messages, msg);
            qd_user_fd_activate_write(tunnel->ufd);
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
    pn_link_open(qd_link_pn(sender));

    tunnel_t *tunnel = DEQ_HEAD(tunnels);
    while (tunnel) {
        if (tunnel->ip_addr) {
            char a4[1000];
            tunnel->ip_link = qd_link(node, conn, QD_INCOMING, "vrx");
            qd_link_set_context(tunnel->ip_link, tunnel);
            snprintf(a4, 1000, "u/%s/%s", tunnel->vlan, tunnel->ip_addr);
            pn_terminus_set_address(qd_link_source(tunnel->ip_link), a4);
            pn_terminus_set_address(qd_link_remote_target(tunnel->ip_link), a4);
            pn_link_open(qd_link_pn(tunnel->ip_link));
            pn_link_flow(qd_link_pn(tunnel->ip_link), 40);
        }
        if (tunnel->ip6_addr) {
            char a6[1000];
            tunnel->ip6_link = qd_link(node, conn, QD_INCOMING, "vrx");
            qd_link_set_context(tunnel->ip6_link, tunnel);
            snprintf(a6, 1000, "u/%s/%s", tunnel->vlan, tunnel->ip6_addr);
            pn_terminus_set_address(qd_link_source(tunnel->ip6_link), a6);
            pn_terminus_set_address(qd_link_remote_target(tunnel->ip6_link), a6);
            pn_link_open(qd_link_pn(tunnel->ip6_link));
            pn_link_flow(qd_link_pn(tunnel->ip6_link), 40);
        }

        tunnel = DEQ_NEXT(tunnel);
    }
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


static const char *bridge_get_env(const char *suffix, int idx)
{
    char var[32];

    snprintf(var, 32, "LANQP_IF%d_%s", idx, suffix);
    return getenv(var);
}


static tunnel_t *bridge_add_tunnel(qd_dispatch_t *_dx, int idx)
{
    tunnel_t *tunnel = NEW(tunnel_t);
    memset(tunnel, 0, sizeof(tunnel_t));
    DEQ_ITEM_INIT(tunnel);
    DEQ_INIT(tunnel->in_messages);

    tunnel->name     = bridge_get_env("NAME", idx);
    tunnel->ns_pid   = bridge_get_env("PID",  idx);
    tunnel->vlan     = bridge_get_env("VLAN", idx);
    tunnel->ip_addr  = bridge_get_env("IP",   idx);
    tunnel->ip6_addr = bridge_get_env("IP6",  idx);

    if (!tunnel->name)
        tunnel->name = "lanq0";

    tunnel->fd = open_tunnel_in_ns(tunnel->name, tunnel->ns_pid);
    if (tunnel->fd == -1) {
        qd_log(log_source, QD_LOG_ERROR, "Tunnel open failed on device %s", tunnel->name);
        exit(1);
    }

    int flags = fcntl(tunnel->fd, F_GETFL);
    flags |= O_NONBLOCK;

    if (fcntl(tunnel->fd, F_SETFL, flags) < 0) {
        qd_log(log_source, QD_LOG_ERROR, "Tunnel failed to set non-blocking: %s", strerror(errno));
        close(tunnel->fd);
        exit(1);
    }

    tunnel->ufd = qd_user_fd(dx, tunnel->fd, tunnel);
    if (tunnel->ufd == 0) {
        qd_log(log_source, QD_LOG_ERROR, "Failed to create qd_user_fd");
        close(tunnel->fd);
        exit(1);
    }

    qd_user_fd_activate_read(tunnel->ufd);
    qd_user_fd_activate_write(tunnel->ufd);

    return tunnel;
}


int bridge_setup(qd_dispatch_t *_dx, const char *ns_pid)
{
    const char *env = getenv("LANQP_IF_COUNT");

    dx = _dx;
    qd_server_set_user_fd_handler(dx, user_fd_handler);

    DEQ_INIT(out_messages);
    DEQ_INIT(tunnels);

    log_source = qd_log_source(MODULE);
    lock = sys_mutex();

    if (!env) {
        printf("Environment variable LANQP_IF_COUNT not set\n");
        exit(1);
    }

    int idx;
    int tunnel_count = atoi(env);
    qd_log(log_source, QD_LOG_INFO, "Tunnel Count: %d", tunnel_count);

    for (idx = 0; idx < tunnel_count; idx++) {
        tunnel_t *tunnel = bridge_add_tunnel(dx, idx);
        DEQ_INSERT_TAIL(tunnels, tunnel);
        qd_log(log_source, QD_LOG_INFO, "    Tunnel Name:      %s", tunnel->name);
        if (tunnel->ns_pid)
            qd_log(log_source, QD_LOG_INFO, "    Tunnel PID:       %s", tunnel->ns_pid);
        qd_log(log_source, QD_LOG_INFO, "    Tunnel VLAN:      %s", tunnel->vlan);
        if (tunnel->ip_addr)
            qd_log(log_source, QD_LOG_INFO, "    Tunnel IP Addr:   %s", tunnel->ip_addr);
        if (tunnel->ip6_addr)
            qd_log(log_source, QD_LOG_INFO, "    Tunnel IPv6 Addr: %s", tunnel->ip6_addr);
    }

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

