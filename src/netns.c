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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <qpid/dispatch/threading.h>
#include "netns.h"

int tun_open(const char *d);

#define PATHLEN 40

typedef struct {
    char        path[PATHLEN];
    const char *device;
    int         fd;
} block_t;


void *thread_run(void *arg)
{
    block_t *block = (block_t*) arg;

    int fd = open(block->path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 0;
    }

    if (setns(fd, 0) < 0) {
        perror("setns");
        close(fd);
        return 0;
    }

    block->fd = tun_open(block->device);

    close(fd);
    return 0;
}


int open_tunnel_in_ns(const char *device, const char *ns_pid)
{
    if (ns_pid == 0)
        return tun_open(device);

    block_t block;
    int     pid = atoi(ns_pid);

    snprintf(block.path, PATHLEN, "/proc/%d/ns/net", pid);
    block.device = device;
    block.fd     = -1;

    sys_thread_t *thread = sys_thread(thread_run, &block);
    sys_thread_join(thread);

    return block.fd;
}


