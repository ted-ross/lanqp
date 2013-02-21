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
#include <proton/driver.h>
#include <qpid/dispatch/server.h>
#include <qpid/dispatch/container.h>
#include <qpid/dispatch/timer.h>
#include <qpid/dispatch/log.h>
#include <qpid/dispatch/buffer.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include "bridge.h"

static int exit_with_sigint = 0;
static char *_host;
static char *_port;
static char *_iface;
static char *_vlan;
static char *_ip;

static void thread_start_handler(void* context, int thread_id)
{
}


static void signal_handler(void* context, int signum)
{
    dx_server_pause();

    switch (signum) {
    case SIGINT:
        exit_with_sigint = 1;

    case SIGQUIT:
    case SIGTERM:
        fflush(stdout);
        dx_server_stop();
        break;

    case SIGHUP:
        break;

    default:
        break;
    }

    dx_server_resume();
}


static void startup(void *context)
{
    dx_server_pause();
    int setup_result = bridge_setup(_host, _port, _iface, _vlan, _ip);
    dx_server_resume();

    if (setup_result < 0)
        dx_server_stop();
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

    dx_server_initialize(2);
    dx_container_initialize();

    dx_server_set_signal_handler(signal_handler, 0);
    dx_server_set_start_handler(thread_start_handler, 0);

    dx_timer_t *startup_timer = dx_timer(startup, 0);
    dx_timer_schedule(startup_timer, 0);

    dx_server_signal(SIGHUP);
    dx_server_signal(SIGQUIT);
    dx_server_signal(SIGTERM);
    dx_server_signal(SIGINT);

    dx_server_run();
    dx_server_finalize();

    if (exit_with_sigint) {
	signal(SIGINT, SIG_DFL);
	kill(getpid(), SIGINT);
    }

    return 0;
}

