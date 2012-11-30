#include <sys/socket.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <time.h>

int tap_open(char *dev);

int main()
{
    char *dev = malloc(10);
    strcpy(dev, "tap0");
    int fd = tap_open(dev);
    int i;
    char buffer[1000];
    char addr[16];

    printf("Tunnel: fd=%d dev=%s\n", fd, dev);

    while (1) {
        ssize_t len = read(fd, buffer, 1000);

        sprintf(addr, "%02X%02X%02X%02X%02X%02X",
                (unsigned char) buffer[0],
                (unsigned char) buffer[1],
                (unsigned char) buffer[2],
                (unsigned char) buffer[3],
                (unsigned char) buffer[4],
                (unsigned char) buffer[5]);

        printf("[ RX to %s (%ld)", addr, len);
        for (i = 0; i < len; i++) {
            printf(" %02x", (unsigned char) buffer[i]);
        }
        printf(" ]\n");
    }
}


