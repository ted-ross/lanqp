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

#include <stdio.h>
#include <qpid/dispatch.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include "bridge.h"

static dx_dispatch_t *dx;

static int exit_with_sigint = 0;
static char *_host;
static char *_port;
static char *_iface;
static char *_vlan;
static char *_ip;

static void thread_start_handler(void* context, int thread_id)
{
}


static void app_signal_handler(void* context, int signum)
{
    dx_server_pause(dx);

    switch (signum) {
    case SIGINT:
        exit_with_sigint = 1;

    case SIGQUIT:
    case SIGTERM:
        fflush(stdout);
        dx_server_stop(dx);
        break;

    case SIGHUP:
        break;

    default:
        break;
    }

    dx_server_resume(dx);
}


static void signal_handler(int signum) {
    dx_server_signal(dx, signum);
}


static void startup(void *context)
{
    dx_server_pause(dx);
    int setup_result = bridge_setup(dx, _host, _port, _iface, _vlan, _ip);
    dx_server_resume(dx);

    if (setup_result < 0)
        dx_server_stop(dx);
}


int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <host> <port> <interface> <vlan> <ip>\n", argv[0]);
        return 1;
    }

    _host  = argv[1];
    _port  = argv[2];
    _iface = argv[3];
    _vlan  = argv[4];
    _ip    = argv[5];

    dx_log_set_mask(LOG_INFO | LOG_ERROR);
    dx_buffer_set_size(1800);

    dx = dx_dispatch(2, "LANQP", 0, 0);

    dx_server_set_signal_handler(dx, app_signal_handler, 0);
    dx_server_set_start_handler(dx, thread_start_handler, 0);

    dx_timer_t *startup_timer = dx_timer(dx, startup, 0);
    dx_timer_schedule(startup_timer, 0);

    signal(SIGHUP,  signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT,  signal_handler);

    dx_server_run(dx);
    dx_dispatch_free(dx);

    if (exit_with_sigint) {
	signal(SIGINT, SIG_DFL);
	kill(getpid(), SIGINT);
    }

    return 0;
}

