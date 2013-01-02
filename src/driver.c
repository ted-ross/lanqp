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


int main()
{
    char *dev = malloc(10);
    strcpy(dev, "tun0");
    int fd = tun_open(dev);
    int i;
    char buffer[MTU];
    char addr_str[200];

    printf("Tunnel: fd=%d dev=%s\n", fd, dev);

    while (1) {
        ssize_t  len = read(fd, buffer, MTU);

	if (len < 20)
	  continue;

	get_dest_addr(buffer, addr_str, 200, "vlan");

        printf("[ RX to %s (%ld)", addr_str, len);
        for (i = 0; i < len; i++) {
            printf(" %02x", (unsigned char) buffer[i]);
        }
        printf(" ]\n");
    }
}


