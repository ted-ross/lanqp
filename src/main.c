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
#include <nexus/server.h>
#include <nexus/container.h>
#include <nexus/timer.h>
#include <nexus/log.h>
#include <signal.h>
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
    nx_server_pause();

    switch (signum) {
    case SIGINT:
        exit_with_sigint = 1;

    case SIGQUIT:
    case SIGTERM:
        fflush(stdout);
        nx_server_stop();
        break;

    case SIGHUP:
        break;

    default:
        break;
    }

    nx_server_resume();
}


static void startup(void *context)
{
    nx_server_pause();
    int setup_result = bridge_setup(_host, _port, _iface, _vlan, _ip);
    nx_server_resume();

    if (setup_result < 0)
        nx_server_stop();
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

    nx_log_set_mask(LOG_INFO | LOG_ERROR);

    nx_server_initialize(2);
    nx_container_initialize();

    nx_server_set_signal_handler(signal_handler, 0);
    nx_server_set_start_handler(thread_start_handler, 0);

    nx_timer_t *startup_timer = nx_timer(startup, 0);
    nx_timer_schedule(startup_timer, 0);

    nx_server_signal(SIGHUP);
    nx_server_signal(SIGQUIT);
    nx_server_signal(SIGTERM);
    nx_server_signal(SIGINT);

    nx_server_run();
    nx_server_finalize();

    if (exit_with_sigint) {
	signal(SIGINT, SIG_DFL);
	kill(getpid(), SIGINT);
    }

    return 0;
}

