#include <pcap.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

static uint64_t packet_counter = 0;

static void print_json_escaped(const char *s) {
    for (const char *p = s; *p; ++p) {
        if (*p == '"' || *p == '\\') putchar('\\');
        putchar(*p);
    }
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *header,
                            const u_char *bytes) {
    (void)user;
    packet_counter++;

    if (header->caplen < sizeof(struct ether_header)) return;
    const struct ether_header *eth = reinterpret_cast<const struct ether_header *>(bytes);

    char src_ip[INET_ADDRSTRLEN] = "-";
    char dst_ip[INET_ADDRSTRLEN] = "-";
    const char *proto = "OTHER";
    int sport = 0, dport = 0;
    uint32_t length = header->len;

    if (ntohs(eth->ether_type) == ETHERTYPE_IP &&
        header->caplen >= sizeof(struct ether_header) + sizeof(struct ip)) {
        const struct ip *iph = reinterpret_cast<const struct ip *>(
            bytes + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iph->ip_dst), dst_ip, INET_ADDRSTRLEN);

        size_t ip_header_len = iph->ip_hl * 4;
        const u_char *l4 = bytes + sizeof(struct ether_header) + ip_header_len;

        switch (iph->ip_p) {
            case IPPROTO_TCP: {
                proto = "TCP";
                const struct tcphdr *tcph = reinterpret_cast<const struct tcphdr *>(l4);
                sport = ntohs(tcph->th_sport);
                dport = ntohs(tcph->th_dport);
                break;
            }
            case IPPROTO_UDP: {
                proto = "UDP";
                const struct udphdr *udph = reinterpret_cast<const struct udphdr *>(l4);
                sport = ntohs(udph->uh_sport);
                dport = ntohs(udph->uh_dport);
                break;
            }
            case IPPROTO_ICMP:
                proto = "ICMP";
                break;
            default:
                proto = "IP";
        }
    } else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
        proto = "ARP";
    }

    printf("{\"id\":%llu,\"ts\":%ld.%06ld,\"src\":\"",
           static_cast<unsigned long long>(packet_counter),
           static_cast<long>(header->ts.tv_sec),
           static_cast<long>(header->ts.tv_usec));
    print_json_escaped(src_ip);
    printf("\",\"dst\":\"");
    print_json_escaped(dst_ip);
    printf("\",\"sport\":%d,\"dport\":%d,\"protocol\":\"%s\",\"length\":%u}\n",
           sport, dport, proto, length);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> [bpf-filter]\n", argv[0]);
        fprintf(stderr, "Example: sudo %s eth0 \"tcp or udp\"\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    const char *filter_exp = (argc >= 3) ? argv[2] : "";

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        fprintf(stderr, "Hint: run as root (Linux) / Administrator (Windows+Npcap).\n");
        return 2;
    }

    if (std::strlen(filter_exp) > 0) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Bad filter '%s': %s\n", filter_exp, pcap_geterr(handle));
            return 3;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
            return 4;
        }
        pcap_freecode(&fp);
    }

    fprintf(stderr, "WIRE-CLOUD raw_capture :: listening on %s (filter: %s)\n",
            iface, filter_exp[0] ? filter_exp : "none");

    pcap_loop(handle, 0, packet_handler, nullptr);
    pcap_close(handle);
    return 0;
}
