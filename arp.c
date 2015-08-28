#include "arp.h"

struct arp_t at;

static char *ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size)
{
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
        hwaddr[0],hwaddr[1],hwaddr[2],hwaddr[3],hwaddr[4],hwaddr[5]);

    return buf;
}

static char *arp_ip2str(u_int8_t *ip, char *buf, socklen_t size)
{
    snprintf(buf, size, "%u.%u.%u.%u",ip[0],ip[1],ip[2],ip[3]);

    return buf;
}

static int build_arp_packet(struct ether_arp *arp)
{
	struct ether_header *eh;
	struct ether_arp *newarp;

	// initialize
	eh = (struct ether_header *)malloc(sizeof(*eh));
	newarp = (struct ether_arp *)malloc(sizeof(*newarp));

	// ethernet header
	memcpy(eh->ether_dhost, arp->arp_sha, ETHER_ADDR_LEN);
	memcpy(eh->ether_shost, at.eth.ether_addr_octet, ETHER_ADDR_LEN);
	eh->ether_type = ETHERTYPE_ARP;


	// arp header	
	newarp->arp_hrd = htons(ARPHRD_ETHER);
	newarp->arp_pro = htons(ETHERTYPE_IP); 
	newarp->arp_hln = ETHER_ADDR_LEN;
	newarp->arp_hln = 4;
	newarp->arp_op = htons(ARPOP_REPLY);

	// copy mac address
	memcpy(newarp->arp_tha, arp->arp_sha, ETHER_ADDR_LEN);
	memcpy(newarp->arp_sha, at.eth.ether_addr_octet, ETHER_ADDR_LEN);

	// copy ip address
	memcpy(newarp->arp_tpa, arp->arp_spa, sizeof(struct in_addr));
	memcpy(newarp->arp_spa, &at.inaddr, sizeof(struct in_addr));

	return 0;
}

static int handle_arp(int sock, unsigned char *data, int len)
{
	unsigned char *p;
	int lest;	
	struct ether_arp *arp;
	char buf[256];

	static char *op[] = {
        "undefine",
        "ARP request",
        "ARP reply",
    };

	p = data;
	lest = len;

	if (lest < sizeof(struct ether_arp)) {
		fprintf(stderr, "lest(%d) < sizeof(struct ether_arp)\n", lest);
		return -1;
	}
	
	arp = (struct ether_arp *)p;
	p += sizeof(struct ether_arp);
	lest -= sizeof(struct ether_arp);

	if (at.debug) {
		printf("srcmac=%s ", ether_ntoa_r(arp->arp_sha, buf, sizeof(buf)));
		printf("dstmac=%s ", ether_ntoa_r(arp->arp_tha, buf, sizeof(buf)));
		printf("srcip=%s ", arp_ip2str(arp->arp_spa, buf, sizeof(buf)));
		printf("dstip=%s ", arp_ip2str(arp->arp_tpa, buf, sizeof(buf)));
		printf("(%s)\n", op[ntohs(arp->arp_op)]);
	}

	arp_ip2str(arp->arp_tpa, buf, sizeof(buf));

	// target ip address is me!
	if (at.inaddr.s_addr == inet_addr(buf)) {
		printf("dstip=%s\n", buf);
		build_arp_packet(arp);
	}

	return 0;
}

static int process_packet(int sock, unsigned char *buf, int len)
{
	unsigned char *p;
	int lest;
	struct ether_header *eh;

	p = buf;
	lest = len;

	if (lest < sizeof(struct ether_header)) {
		fprintf(stderr, "lest(%d) < sizeof(struct ether_header)\n", lest);
		return -1;
	}

	eh = (struct ether_header *)p;
	p += sizeof(struct ether_header);
	lest -= sizeof(struct ether_header);

	if (ntohs(eh->ether_type) == ETHERTYPE_ARP)  
		handle_arp(sock, p, lest);

	return 0;
}

static void get_local_address(struct arp_t *p)
{
	int sock;
	struct ifreq ifr;
	char *dev = p->dev;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	// IP Address
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl");
		close(sock);
		exit(1);
	}
	p->inaddr.s_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

	// MAC Address
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl");
		close(sock);
		exit(1);
	}
   	memcpy(&(p->eth), ifr.ifr_hwaddr.sa_data, ETH_ALEN);
}

static int create_socket(char *dev)
{
	struct ifreq ifr;
	struct sockaddr_ll saddr;
	int sock;

	memset(&ifr, 0, sizeof(struct ifreq));
	memset(&saddr, 0, sizeof(struct sockaddr_ll));

	if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket");
		exit(1);
	}

	strcpy(ifr.ifr_name, dev);
	if (ioctl (sock, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl");
		close(sock);
		exit(1);
	}

	saddr.sll_family = PF_PACKET;
	saddr.sll_ifindex = ifr.ifr_ifindex;
	saddr.sll_protocol = htons (ETH_P_ALL);

	if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		perror("bind");
		close(sock);
		return -1;
	}

	ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC;
	if (ioctl (sock, SIOCGIFFLAGS, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	return sock;
}

static void init_arp_data(struct arp_t *p)
{
    p->debug = 0;
    p->daemon = 0;
	memset(p->dev, 0, sizeof(DEVSIZE));
}

static void usage()
{
    fprintf(stderr, "Usage:\n");
	fprintf(stderr, "arproxyd -i <interface>\n");
    fprintf(stderr, "-v: outputs debug infomation while running\n");
    fprintf(stderr, "-d: running process as daemon\n");
    fprintf(stderr, "-h: output this usage\n");
    exit(1);
}

int main(int argc, char **argv)
{
	int opt, len;
	unsigned char buf[BUFSIZE];

	if (argc <= 1) {
		fprintf(stderr, "Too few options\n");
		usage();
	}

	// initialize arp data
	init_arp_data(&at);

	while ((opt = getopt(argc, argv, "hi:vd")) > 0) {
		switch (opt) {
		case 'h':
			usage();
			break;
		case 'i':
			strncpy(at.dev, optarg, DEVSIZE - 1);
			break;
		case 'v':
			at.debug = 1;
			break;
		case 'd':
			at.daemon = 1;
			break;
		default:
			fprintf(stderr, "Unknown option %c\n", opt);
			usage();
		}
	}

	argv += optind;
	argc -= optind;

    if (argc > 0) {
        fprintf(stderr, "Too many options\n");
        usage();
    }

	if (at.debug)
		printf("Interface: %s\n", at.dev);

	// deamonize if daemon flag
	if (at.daemon) {
		if ((daemon(1,1)) != 0) {
			perror("daaemon");
			exit(1);
        }
    }

	// create raw socket
	at.sock = create_socket(at.dev);
	if (at.debug)
		printf("Create socket\n");

	// get local address
	get_local_address(&at);

	if (at.debug) {
		printf("IPAddress: %s\n", inet_ntoa(at.inaddr));
		printf("MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",
				at.eth.ether_addr_octet[0], at.eth.ether_addr_octet[1],
				at.eth.ether_addr_octet[2], at.eth.ether_addr_octet[3], 
				at.eth.ether_addr_octet[4], at.eth.ether_addr_octet[5]);
	}

	while (1) {
		if ((len = read(at.sock, buf, sizeof(buf))) <= 0)
			perror("read");
		else
			process_packet(at.sock, buf, len);
	}

	return 0;
}
