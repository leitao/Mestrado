/*
 * sendmmsg microbenchmark.
 * Modified by Breno Leitao to run some benchmark against sendmsg
 *
 * Build with:
 *
 * gcc -O2 -o sendmmsg_test sendmmsg_test.c
 *
 * Copyright (C) 2011 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <asm/unistd.h>

#ifndef __NR_sendmmsg
#if defined( __PPC__)
#define __NR_sendmmsg	349
#elif defined(__x86_64__)
#define __NR_sendmmsg	307
#elif defined(__i386__)
#define __NR_sendmmsg	345
#else
#error __NR_sendmmsg not defined
#endif
#endif

struct mmsghdr {
	struct msghdr msg_hdr;
	unsigned int msg_len;
};

int sendmmsg_enabled;
int sec = 0;

static inline int sendmmsg(int fd, struct mmsghdr *mmsg, unsigned vlen,
			   unsigned flags)
{
	return syscall(__NR_sendmmsg, fd, mmsg, vlen, flags, NULL);
}

static unsigned long packets;
static unsigned long packets_prev;
int packet_size;
int batch_size;

static void do_sendmmsg(int fd, struct sockaddr *addr, unsigned int packet_size,
			unsigned int batch_size, char *b)
{
	unsigned int i;
	char buf[batch_size][packet_size];
	struct iovec iovec[batch_size][1];
	struct mmsghdr datagrams[batch_size];

	memset(buf, 0, sizeof(buf));
	memset(iovec, 0, sizeof(iovec));
	memset(datagrams, 0, sizeof(datagrams));

	for (i = 0; i < batch_size; ++i) {
		memcpy(&buf[i], b, sizeof(buf[i]));
		iovec[i][0].iov_base = buf[i];
		iovec[i][0].iov_len = sizeof(buf[i]);
		datagrams[i].msg_hdr.msg_iov = iovec[i];
		datagrams[i].msg_hdr.msg_iovlen = 1;
		if (addr) {
			datagrams[i].msg_hdr.msg_name = addr;
			datagrams[i].msg_hdr.msg_namelen = sizeof(*addr);
		}
	}

	while (1) {
		int ret;
		int z;

		if (!sendmmsg_enabled){
			for (z = 0; z<batch_size; z++){
				ret = sendmsg(fd, &datagrams[i].msg_hdr, 0);
			}
			ret += batch_size;
		
		} else {
			ret = sendmmsg(fd, datagrams, batch_size, 0);

			if (ret < 0) {
				perror("sendmmsg");
				exit(1);
			}

			if (ret != batch_size) {
				fprintf(stderr,
					"sendmmsg returned sent less than batch\n");
			}
		}


		packets += ret;
		ret = 0;
	}
}

static void do_udp(const char *host, const char *port, int packet_size,
		   int batch_size)
{
	int ret;
	struct addrinfo *ainfo;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP,
		.ai_flags = AI_PASSIVE,
	};
	int fd;
	int i;
	char buf[packet_size];
	int z;

	ret = getaddrinfo(host, port, &hints, &ainfo);
	if (ret) {
		fprintf(stderr, "error using getaddrinfo: %s\n",
			gai_strerror(ret));
		exit(1);
	}

	fd = socket(ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol);
	if (fd == -1) {
		perror("socket");
		exit(1);
	}

	for (i = 0; i < sizeof(buf); i++)
		buf[i]= i;

	do_sendmmsg(fd, ainfo->ai_addr, packet_size, batch_size, buf);
}

static int open_raw_socket(int interface)
{
	int sock;
	struct sockaddr_ll skt;
	int size;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock == -1) {
		perror("socket");
		exit(1);
	}

	memset(&skt, 0, sizeof(struct sockaddr_ll));
	skt.sll_family = AF_PACKET;
	skt.sll_protocol = htons(ETH_P_ALL);
	skt.sll_ifindex = interface;

	if (bind(sock, (struct sockaddr *)&skt, sizeof(struct sockaddr_ll))) {
		perror("bind");
		exit(1);
	}

	size = 128*1024*1024UL;
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &size,
	    sizeof(size)) == -1) {
		perror("setsockopt");
		exit(1);
	}

	return sock;
}

static void do_raw(const char *interface, int packet_size, int batch_size)
{
	int iface;
	int fd;
	struct ifreq ifr;
	char source_mac[ETH_ALEN];
	/*
	 * Random target address. The 0x2 in the first byte means this
	 * is a locally assigned address.
	 */
	char dest_mac[ETH_ALEN] = { 0x2, 0xd, 0x0, 0x0, 0xd, 0x5};
	int i;
	char buf[packet_size];

	iface = if_nametoindex(interface);
	if (iface == 0) {
		fprintf(stderr, "Interface %s not found\n", interface);
		exit(1);
	}

	fd = open_raw_socket(iface);

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	memcpy(source_mac, ifr.ifr_hwaddr.sa_data, sizeof(source_mac));

	memcpy(&buf[0], dest_mac, ETH_ALEN);
	memcpy(&buf[ETH_ALEN], source_mac, ETH_ALEN);

	for (i = 2 * ETH_ALEN; i < sizeof(buf); i++)
		buf[i]= i;

	do_sendmmsg(fd, NULL, packet_size, batch_size, buf);
}

static void sigalrm_handler(int junk)
{
	unsigned long p = packets;

	printf("%d %d %ld\n", sendmmsg_enabled, batch_size, p - packets_prev/20);
	packets_prev = p;
	exit(0);
}

static void usage(void)
{
	fprintf(stderr, "Usage: sendmmsg_test -u <host> <port> <packet_size> "
			"<batch_size>\n");
	fprintf(stderr, "       sendmmsg_test -r <interface> <packet_size> "
			"<batch_size>\n");
}

int main(int argc, char *argv[])
{
	const char *host;
	const char *port;
	const char *interface;

	if (argc != 7 && argc != 6) {
		usage();
		exit(1);
	}

	signal(SIGALRM, sigalrm_handler);
	alarm(10);

	if (!strcmp(argv[1], "-u")) {
		host = argv[2];
		port = argv[3];
		packet_size = atoi(argv[4]);
		batch_size = atoi(argv[5]);
		sendmmsg_enabled = atoi(argv[6]);
		do_udp(host, port, packet_size, batch_size);

	} else if (!strcmp(argv[1], "-r")) {
		interface = argv[2];
		packet_size = atoi(argv[3]);
		batch_size = atoi(argv[4]);
		sendmmsg_enabled = atoi(argv[5]);
		do_raw(interface, packet_size, batch_size);

	} else {
		usage();
		exit(1);
	}

	return 0;
}
