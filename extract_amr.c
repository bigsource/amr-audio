/* 
 * author: 317150231@qq.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>

#include <pcap.h>
#include <stdbool.h>
#include <assert.h>

struct UDP_hdr {
    u_short    uh_sport;        /* source port */
    u_short    uh_dport;        /* destination port */
    u_short    uh_ulen;        /* datagram length */
    u_short    uh_sum;            /* datagram checksum */
};

bool is_amr_wb = false;
bool is_oa_mode = false;
char *input_file_name = NULL;
char *output_file_name = NULL;
FILE *output_file_fd = NULL;
int dst_port =0;
int ts_step = 0; // timestamp step, 160 for amrnb, 320 for amrwb

int frame_number = 0;

#define FT_Invalid 0xFFFF
const unsigned short AmrBits[]={95,103,118,134,148,159,204,244,39,FT_Invalid,FT_Invalid,FT_Invalid,FT_Invalid,
                             FT_Invalid, FT_Invalid,0};
const unsigned short AmrWBBits[]={132,177,253,285,317,365,397,461,477,40,FT_Invalid,FT_Invalid,FT_Invalid,
                             FT_Invalid, FT_Invalid,0};
const unsigned char NODATA_FRAME = 0x7C;
#define RTP_HEAD_LEN 12

void help();
void hexDump(const void *addr, int len);

void write_bits_saft(char **to, const unsigned char **from, int *to_bit_offset, int *from_bit_offset, int num_bit) {
    assert((*from_bit_offset) + num_bit <= 8);
    assert((*to_bit_offset) + num_bit <= 8);
    unsigned char tmp;
    tmp = *(*from);
    tmp = tmp & ((1<<(8 - *from_bit_offset)) - 1);
    tmp = (tmp>>(8 - *from_bit_offset - num_bit));
    tmp = tmp<<(8 - num_bit - (*to_bit_offset));
    (**to) = (**to) | tmp;
    (*to_bit_offset) += num_bit;
    if((*to_bit_offset) == 8) {
        (*to)++;
        *to_bit_offset = 0;
    }
    *from_bit_offset += num_bit;
    if((*from_bit_offset) == 8) {
        (*from)++;
        (*from_bit_offset) = 0;
    }
}

void write_single_byte_bits(char **to, const unsigned char **from, int *to_bit_offset, int *from_bit_offset, int num_bit) {
    //printf("to_bit_offset %d, from_bit_offset %d, num_bit %d\n", *to_bit_offset, *from_bit_offset, num_bit);

    assert((*from_bit_offset) + num_bit <= 8);
    int to_bit_remain = 8 - (*to_bit_offset);
    if(to_bit_remain < num_bit) {
        write_bits_saft(to, from, to_bit_offset, from_bit_offset, to_bit_remain);
        num_bit -= to_bit_remain;
    }

    assert((*to_bit_offset) + num_bit <= 8);
    write_bits_saft(to, from, to_bit_offset, from_bit_offset, num_bit);
    
}

void write_multi_bytes_bits(char *to, const unsigned char **from, int *to_bit_offset, int *from_bit_offset, int num_bit) {
    //printf("to_bit_offset %d, from_bit_offset %d, num_bit %d\n", *to_bit_offset, *from_bit_offset, num_bit);
    int input_bit_remain = 0;
    while(num_bit > 0) {
        input_bit_remain = 8 - (*from_bit_offset);
        if(input_bit_remain > num_bit) {
            write_single_byte_bits(&to, from, to_bit_offset, from_bit_offset, num_bit);
            num_bit = 0;
        } else if(input_bit_remain <= num_bit){
            write_single_byte_bits(&to, from, to_bit_offset, from_bit_offset, input_bit_remain);
            num_bit = num_bit - input_bit_remain;
        }
    }
}

void create_amr_file() {
    if(output_file_name == NULL) {
        return;
    }
    output_file_fd = fopen(output_file_name,"wb");
    if(output_file_fd == NULL) {
        return;
    }
    if(is_amr_wb) {
        fprintf(output_file_fd, "#!AMR-WB\n");
    } else {
        fprintf(output_file_fd, "#!AMR\n");
    }
    return;
}

bool checkParams() {
    if(input_file_name == NULL) {
        printf("input file name needed,usage example\n");
        help();
        return false;
    }
    if(dst_port == 0) {
        printf("need to set dstination port,usage example\n");
        help();
        return false;
    }
    if(output_file_name == NULL) {
        int file_name_len = strlen(input_file_name);
        int dot_index = file_name_len;
        int index = 0;
        output_file_name = malloc(file_name_len + 4);
        memset(output_file_name, 0, file_name_len + 4);
        memcpy(output_file_name, input_file_name, file_name_len);
        for(index = file_name_len-1; index > 0; --index) {
            if(output_file_name[index] == '.') {
                dot_index = index;
                break;
            }
        }
        memcpy(&output_file_name[dot_index], ".amr", 5);
    }
    printf("input file %s\n", input_file_name);
    printf("output file %s\n", output_file_name);
    printf("is_amr_wb %d\n", is_amr_wb);
    printf("is_oa_mode %d\n", is_oa_mode);
    return true;
}

void write_AMR_OA_mode(const unsigned char *packet, unsigned int capture_len) {
}

void write_AMR_BE_mode(const unsigned char *packet, unsigned int capture_len) {
    char cmr = 0;
    char ft = 0;
    char outAmrBuffer[100];
    int amr_len = 0;
    memset(outAmrBuffer, 0, sizeof(outAmrBuffer));
    int from_bit_offset = 0;
    int to_bit_offset = 4;
    //hexDump(packet, 32);
    write_multi_bytes_bits(&cmr, &packet, &to_bit_offset, &from_bit_offset, 4);
    //printf("cmr %x\n", cmr);
    to_bit_offset = 2;
    write_multi_bytes_bits(&ft,  &packet, &to_bit_offset, &from_bit_offset, 6);
    if(ft & (1<<5)) {
        // TODO:support multi frame in one packet here
        assert(0);
    }
    ft = (ft>>1);
    //printf("ft %x\n", ft);
    
    if(is_amr_wb) {
        assert(ft >= 0 && ft <= 9);
        amr_len = (AmrWBBits[ft] + 7)/8;
    } else {
        assert(ft >= 0 && ft <= 8);
        amr_len = (AmrBits[ft] + 7)/8;
    }
    to_bit_offset = 0;
    write_multi_bytes_bits(outAmrBuffer,  &packet, &to_bit_offset, &from_bit_offset, amr_len*8);
    ft = ((ft<<3) | 4);
    fwrite(&ft, 1, 1, output_file_fd);
    fwrite(outAmrBuffer, amr_len, 1, output_file_fd);
    return;
}


/* Returns a string representation of a timestamp. */
const char *timestamp_string(struct timeval ts);


/* Report the specific problem of a packet being too short. */
void too_short(struct timeval ts, const char *truncated_hdr);
void parse_RTP_packet(const unsigned char *packet, struct timeval ts,
            unsigned int capture_len);

void parse_UDP_packet(const unsigned char *packet, struct timeval ts, unsigned int capture_len) {
    struct ip *ip;
    struct ip6_hdr *ip6;
    struct UDP_hdr *udp;
    unsigned int IP_header_length;
    /* For simplicity, we assume Ethernet encapsulation. */

    if (capture_len < sizeof(struct ether_header))
    {
        /* We didn't even capture a full Ethernet header, so we
         * can't analyze this any further.
         */
        too_short(ts, "Ethernet header");
        return;
    }
    /* Skip over the Ethernet header. */
    packet += sizeof(struct ether_header);
    capture_len -= sizeof(struct ether_header);
    
    ip = (struct ip*) packet;
    ip6 = (struct ip6_hdr*) packet;
    if(ip->ip_v == 4) {
        if (capture_len < sizeof(struct ip)) {
            too_short(ts, "ip header");
            return;
        }
        IP_header_length = sizeof(struct ip);
        
    } else if(ip->ip_v == 6) {
        if (capture_len < sizeof(struct ip6_hdr)) {
            too_short(ts, "ip6 header");
            return;
        }
        IP_header_length = sizeof(struct ip6_hdr);
    }
    /* Skip over the IP header to get to the UDP header. */
    packet += IP_header_length;
    capture_len -= IP_header_length;


    udp = (struct UDP_hdr*) packet;
    if(dst_port != 0 && ntohs(udp->uh_dport) != dst_port)
        return;

    /*printf("%s src_port=%d dst_port=%d,",
        timestamp_string(ts),
        ntohs(udp->uh_sport),
        ntohs(udp->uh_dport));*/

    int udp_len = sizeof(struct UDP_hdr);
    parse_RTP_packet(packet + udp_len, ts, capture_len - udp_len);
}

void parse_RTP_packet(const unsigned char *rtp_packet, struct timeval ts, unsigned int capture_len) {
    assert(capture_len > RTP_HEAD_LEN);
    static struct timeval last_time;
    static unsigned int last_ssrc = 0;
    static unsigned short last_sequence = 0;
    static unsigned int last_timestamp = 0;
    unsigned char rtp_version = *rtp_packet;
    unsigned int ssrc = ntohl(*(unsigned int *)(rtp_packet+8));
    unsigned int timestamp = ntohl(*(unsigned int *)(rtp_packet+4));
    unsigned short sequence = ntohs(*(unsigned short *)(rtp_packet+2));
    if(rtp_version != 0x80) {
        printf("%s error!\n", __FUNCTION__);
        return;
    }
    printf("%s sequence=%u, timestamp %u\r", __FUNCTION__, sequence, timestamp);
    if(last_ssrc == ssrc) {
        if(sequence <= last_sequence && (last_sequence - sequence < 1000))
            return; // discard duplicate frame, older frame

        // during SID period, timestamp maybe jump, need to insert nodata frame here.
        // if frame lost in network, nodate frame also need to insert
        if(timestamp > last_timestamp + ts_step)
            printf("%s write nodata frame last_timestamp %d, timestamp %d\n", __FUNCTION__, last_timestamp, timestamp);
        while(timestamp > last_timestamp + ts_step) {
            fwrite(&NODATA_FRAME, 1, 1, output_file_fd);
            last_timestamp += ts_step;
            frame_number++;
        }
    }
    last_ssrc = ssrc;
    last_sequence = sequence;
    last_timestamp = timestamp;
    frame_number++;
    if(is_oa_mode) {
        write_AMR_OA_mode(rtp_packet+RTP_HEAD_LEN, capture_len-RTP_HEAD_LEN);
    } else {
        write_AMR_BE_mode(rtp_packet+RTP_HEAD_LEN, capture_len-RTP_HEAD_LEN);
    }
    return;
}

void help() {
    printf("---------command for usage ---------\n");
    printf("-h (optional) get help information\n");
    printf("-i (mandatory) set input pcap file name to analyse\n");
    printf("-o (optional) set output pcap file name to analyse\n");
    printf("-w (optional) set for amr-wb codec. amr-nb codec if not set\n");
    printf("-a (optional) set for Octet-Aligned, Bandwidth-Efficient if not set\n");
    printf("-d (optional) set destination port to extract, else all port would be extracted\n");
    printf("example 1: ./extract_amr.out -i exported_tr.pcap\n");
    printf("example 2: ./extract_amr.out -i exported_tr.pcap -w -a\n");
    printf("------------------------------------\n");
    return;
}
int main(int argc, char *argv[]) {
    pcap_t *pcap;
    const unsigned char *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    int opt;
    extern char *optarg;
    int str_len;
    if(argc == 1) {
        help();
        return;
    }
    while((opt = getopt(argc, argv, ":i:o:d:hwa")) != -1) {
        switch(opt) {
        case 'i':
            str_len = strlen(optarg) + 1;
            input_file_name = malloc(str_len);
            memset(input_file_name, 0, str_len);
            memcpy(input_file_name, optarg, str_len);
            printf("input file name is %s\n", input_file_name);
            break;
        case 'o':
            str_len = strlen(optarg) + 1;
            output_file_name = malloc(str_len);
            memset(output_file_name, 0, str_len);
            memcpy(output_file_name, optarg, str_len);
            printf("output file name is %s\n", output_file_name);
            break;
        case 'w':
            is_amr_wb = true;
            printf("is_amr_wb %d\n", is_amr_wb);
            break;
        case 'a':
            is_oa_mode = true;
            printf("is_oa_mode %d\n", is_oa_mode);
            break;
        case 'd':
            dst_port = atoi(optarg);
            printf("dst_port %d\n", dst_port);
            break;
        case 'h':
            help();
            break;
        default:
            printf("not support %c\n", opt);
            break;
        }
    }

    if(!checkParams()) {
        return;
    }
    if(is_amr_wb)
        ts_step = 320;
    else 
        ts_step = 160;
    create_amr_file();

    pcap = pcap_open_offline(input_file_name, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "error reading pcap file: %s\n", errbuf);
        exit(1);
    }

    /* Now just loop through extracting packets as long as we have
     * some to read.
     */
    while ((packet = pcap_next(pcap, &header)) != NULL)
        parse_UDP_packet(packet, header.ts, header.caplen);
    printf("total frames %d\n", frame_number);
    printf("-------------------process complete!-------------------\n");
    fclose(output_file_fd);
    return 0;
}


/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char *timestamp_string(struct timeval ts) {
    static char timestamp_string_buf[256];
    int hour = (ts.tv_sec/3600)%24;
    int minute = (ts.tv_sec%3600)/60;
    int second = ts.tv_sec%60;

    sprintf(timestamp_string_buf, "%d:%d:%d.%06d",
        hour, minute, second, (int) ts.tv_usec);

    return timestamp_string_buf;
}


void too_short(struct timeval ts, const char *truncated_hdr) {
    fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
    timestamp_string(ts), truncated_hdr);
}

void hexDump(const void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf("  %s\n", buff);

            // Output the offset.
            printf("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf(" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % 16] = '.';
        } else {
            buff[i % 16] = pc[i];
        }

        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf("  %s\n", buff);
}

