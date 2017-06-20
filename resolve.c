#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void dump(char *answer, int len);
void dump_ns(char *answer, int len);
int main(int argc, char *argv[]) {
    char *host = argv[1];
    int len, rv;
    char answer[PACKETSZ];

    rv = res_init();
    printf("res_init returns %d\n", rv);
    len = res_search(host, C_IN, T_TXT, answer, sizeof(answer));
    printf("res_query returns %d\n", len);
    if (len > 0) {
        dump(answer, len);
        dump_ns(answer, len);
    }
    return 0;
}
void dump(char *answer, int len) {
    int i;
    for(i=0; i<len; i++) {
        if (i%16 == 0) printf("%05d - ", i);
        printf("%02x ", (unsigned char)answer[i]);
        if (i%16 == 15) {
            char line[128];
            int j;
            memcpy(line, answer+i-15, 16);
            line[16] = 0;
            for(j=0; j<16; j++) line[j] = line[j] >= ' ' ? line[j] : '.';
            printf(" - %s\n", line);
        }
    }
    printf("\n");
}

#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>
void dump_ns_section(char *title, ns_msg handle, ns_sect section);
void dump_ns(char *answer, int len) {
    int rv;
    ns_msg handle;
    rv = ns_initparse(answer, len, &handle);
    printf("ns_initparse returns %d\n", rv);
    if (rv < 0) return;

    dump_ns_section("Question", handle, ns_s_qd);
    dump_ns_section("Answer", handle, ns_s_an);
    dump_ns_section("Name Server", handle, ns_s_ns);
    dump_ns_section("Additional", handle, ns_s_ar);
}

#include <arpa/inet.h>
void dump_ns_section(char *title, ns_msg handle, ns_sect section) {
    int count = ns_msg_count(handle, section), rrnum;
    printf("==Section [%s] count %d==\n", title, count);
    for(rrnum = 0; rrnum < count; rrnum++) {
        ns_rr rr;
        int rv = ns_parserr(&handle, section, rrnum, &rr);
        const unsigned char *raw = ns_rr_rdata(rr);
        int len = ns_rr_rdlen(rr);
        printf("%d/%d :", rrnum, count);
        printf("  Name[%s] TTL%d", ns_rr_name(rr), ns_rr_ttl(rr));
        if (ns_rr_class(rr) != C_IN) printf("  Class[%d]\n", ns_rr_class(rr));
        if (len == 0) {
            printf(" Type [%d]\n", ns_rr_type(rr));
        }
        else if (ns_rr_type(rr) == ns_t_mx) {
            int value = raw[0]*256 + raw[1];
            char data[MAXDNAME];
            rv = ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), raw+2, data, sizeof(data));
            if (rv < 0) printf("*ERR uncompress fail\n");
            else printf(" MX %d [%s]\n", value, data);
        }
        else if (ns_rr_type(rr) == ns_t_ns) {
            char data[MAXDNAME];
            rv = ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), ns_rr_rdata(rr), data, sizeof(data));
            if (rv < 0) printf("*ERR uncompress fail\n");
            else printf(" NS [%s]\n", data);
        }
        else if (ns_rr_type(rr) == ns_t_a) {  // IPv4
            char data[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, raw, data, sizeof(data)) == NULL) printf("*ERR IPv4 address\n");
            else printf(" A [%s]\n", data);
        }
        else if (ns_rr_type(rr) == ns_t_aaaa) {  // IPv6
            char data[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, raw, data, sizeof(data)) == NULL) printf("*ERR IPv6 address\n");
            else printf(" AAAA [%s]\n", data);
        }
        else if (ns_rr_type(rr) == ns_t_txt) { // TXT
            char data[1024];
            int txt_len = raw[0];
            memcpy(data, raw+1, txt_len);
            data[txt_len] = 0;
            printf(" TXT [%s]\n", data);
        }
        else if (len > 0) {
            printf(" Type [%d]", ns_rr_type(rr));
            printf(" rdlen[%d]\n", ns_rr_rdlen(rr));
            //printf(" Data [%s]\n", ns_rr_rdata(rr));
            dump(raw, len);
        }
    }
}

