#include "arp.h"

static int handle_packet(int sock, unsigned char *buf, int len)
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
        printf("ARP: Packet[%dbytes]\n", len);

	return 0;
}

static void get_local_address(struct arp_t *p)
{
	int sock;
	struct ifreq ifr;
	char *dev = p->dev;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket:");
		exit(1);
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	// IP Address
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl:");
		close(sock);
		exit(1);
	}
	p->inaddr.s_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

	// MAC Address
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl:");
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
		perror("socket:");
		exit(1);
	}

	strcpy(ifr.ifr_name, dev);
	if (ioctl (sock, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl:");
		close(sock);
		exit(1);
	}

	saddr.sll_family = PF_PACKET;
	saddr.sll_ifindex = ifr.ifr_ifindex;
	saddr.sll_protocol = htons (ETH_P_ALL);

	if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		perror("bind:");
		close(sock);
		return -1;
	}

	ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC;
	if (ioctl (sock, SIOCGIFFLAGS, &ifr) < 0) {
		perror("ioctl:");
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
	int opt, sock, len;
	struct arp_t at;
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
			perror("daaemon: ");
			exit(1);
        }
    }

	// create raw socket
	sock = create_socket(at.dev);
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
		if ((len = read(sock, buf, sizeof(buf))) <= 0)
			perror("read");
		else
			handle_packet(sock, buf, len);
	}

	return 0;
}
