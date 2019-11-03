#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <errno.h>
#include <stdint.h>

#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

#define max(a,b) (a > b ? a : b) 
#define min(a,b) (a < b ? a : b) 

uint32_t pow(uint32_t a, uint32_t n){ // return a^n
	uint32_t result = 1;
	while(n--){
		result *= a;
	}
	return result;
}

void usage() {
    printf("syntax: netfilter_block <host>\n");
    printf("sample: netfilter_block test.gilgil.net\n");
}

void print_mac(u_char * mac){
	for(int i = 0; i < 6; i++){
		printf("%02x", *(mac+i));
		if(i == 5) break;
		printf(":");
	}
	printf("\n");
}
void print_ip(u_char * ip){
	for(int i = 0; i < 4; i++){
		printf("%d", *(ip+i));
		if(i == 3) break;
		printf(".");
	}
	printf("\n");
}

uint16_t ethernet_protocol_type;
uint8_t ipv4_protocol_id;

// Layer 7
void Data_print(u_char * packet, uint32_t start, uint32_t max_size){
	uint32_t end = start + 32;
	end = min(end, max_size);
	Data_check(start, end);
	printf("\n");
}

// Layer 4
uint32_t TCP_print(u_char * packet, uint32_t start){
	uint32_t tcp_start = start;

	uint32_t tcp_src_port_start = tcp_start, tcp_src_port_end = tcp_start + 1;
	uint16_t tcp_src_port_num = packet[tcp_src_port_start] * 256 + packet[tcp_src_port_end];
	printf("(TCP) Source port: %d\n", tcp_src_port_num);

	uint32_t tcp_dst_port_start = tcp_src_port_end + 1, tcp_dst_port_end = tcp_dst_port_start + 1;
	uint16_t tcp_dst_port_num = packet[tcp_dst_port_start] * 256 + packet[tcp_dst_port_end];
	printf("(TCP) Destination port: %d\n", tcp_dst_port_num);

	uint32_t tcp_header_length = (packet[tcp_start + 12] & 0xf0) >> 2;
	printf("(TCP) Header Length: %d bytes\n", tcp_header_length);

	return tcp_start + tcp_header_length;
}

// Layer 3
uint32_t IPv4_print(u_char * packet, uint32_t start){
	uint32_t ipv4_start = start;

	uint32_t ipv4_header_length = (packet[ipv4_start] & 0x0f) * 4;
	printf("(IPv4) Header Length: %d bytes\n", ipv4_header_length);

	uint32_t ipv4_protocol_ID = packet[ipv4_start + 9];
	ipv4_protocol_id = ipv4_protocol_ID;
	printf("(IPv4) Protocol ID %d\n", ipv4_protocol_ID);

	printf("(IPv4) IP source address ");
	uint32_t ipv4_src_addr_start = ipv4_start + 12;
	print_ip(packet + ipv4_src_addr_start);

	printf("(IPv4) IP destination address ");
	uint32_t ipv4_dst_addr_start = ipv4_start + 16;
	print_ip(packet + ipv4_dst_addr_start);

	return ipv4_start + ipv4_header_length;
}

bool now_packet_accept = true;
void dump(unsigned char* buf, int size) {
	// packet which includes host_name must be dropped (by now_packet_accept)
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0) printf("\n");
		printf("%02x ", buf[i]);
	}
	printf("\n\n");

	uint32_t ipv4_header_end = 0;
	uint32_t tcp_header_end = 0;

    ipv4_header_end = IPv4_print(buf, 0);
    if(ipv4_protocol_id == 0x6){ // IPv4 -> TCP
    	tcp_header_end = TCP_print(buf, ipv4_header_end);
    }
    Data_print(buf, max(ipv4_header_end, tcp_header_end), size);
    printf("\n");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	dump(data, ret);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if(now_packet_accept) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	else return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if (argc != 2){
        usage();
        return -1;
    }
	char * host_name = argv[1];

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

