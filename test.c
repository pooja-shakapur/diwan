#include <stdio.h> //input-output
#include <sys/types.h>//define data types used in s/m source code
#include <sys/socket.h>//it should has at least 32 bits
#include <netinet/in.h>//contains defination for the internet protocol family
#include <arpa/inet.h>//defination for internet operations
#include <netdb.h>//defination of n/w database operations
#include <unistd.h>//standard symbolic constant and types
#include <string.h>//it defines variable types
#include <stdlib.h>//libraries
#include <netinet/ip_icmp.h>//internet of icmp
#include <time.h>//accessing date time
#include <fcntl.h>//file control
#include <signal.h>//signal handler
#include <time.h>//accessing time data

#define PING_PKT_S 64		
#define PORT_NO 0			
#define PING_SLEEP_RATE 1000000	
#define RECV_TIMEOUT 1		
int pingloop=1;				
struct ping_pkt				
{
	struct icmphdr hdr;
	char msg[PING_PKT_S-sizeof(struct icmphdr)];
};
unsigned short checksum(void *b, int len)		
{ unsigned short *buf = b;
	unsigned int sum=0;
	unsigned short result;
	for ( sum = 0; len > 1; len -= 2 )
		sum += *buf++;
	if ( len == 1 )
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}
void intHandler(int dummy) //interrupt handler		
{
	pingloop=0;
}
char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con)		
{
	printf("....Resolving DNS....");
	struct hostent *host_entity;
	char *ip=(char*)malloc(NI_MAXHOST*sizeof(char));
	int i;
	if ((host_entity = gethostbyname(addr_host)) == NULL)
	{
		return NULL;			
	}
	//filling address structure	
	strcpy(ip, inet_ntoa(*(struct in_addr *) host_entity->h_addr));	
	(*addr_con).sin_family = host_entity->h_addrtype;
	(*addr_con).sin_port = htons (PORT_NO);
	(*addr_con).sin_addr.s_addr = *(long*)host_entity->h_addr;
	return ip;	
}
char* reverse_dns_lookup(char *ip_addr)		
{
	struct sockaddr_in temp_addr;
	socklen_t len;
	char buf[NI_MAXHOST], *ret_buf;
	temp_addr.sin_family = AF_INET;
	temp_addr.sin_addr.s_addr = inet_addr(ip_addr);
	len = sizeof(struct sockaddr_in);
	if (getnameinfo((struct sockaddr *) &temp_addr, len, buf, sizeof(buf), NULL, 0, NI_NAMEREQD))
	{
		printf("Could not resolve reverse lookup of hostname..");
		return NULL;
	}
	ret_buf = (char*)malloc((strlen(buf) +1)*sizeof(char) );
	strcpy(ret_buf, buf);
	return ret_buf;
}

//ping request
void send_ping(int ping_sockfd,struct sockaddr_in *ping_addr,char *ping_dom, char *ping_ip, char *rev_host)
{
	int ttl_val=64, msg_count=0, i, addr_len, flag=1, msg_received_count=0;	
	struct ping_pkt pckt;
	struct sockaddr_in r_addr;
	struct timespec time_start, time_end, tfs, tfe;
	long double rtt_msec=0, total_msec=0;
	struct timeval tv_out;
	tv_out.tv_sec = RECV_TIMEOUT;
	tv_out.tv_usec = 0;
	clock_gettime(CLOCK_MONOTONIC, &tfs);	
	
	if (setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0)	{
		printf("..Setting socket options to TTL failed!..");
		return;
	}
	else {
		printf("...Socket set to TTL...");
	}
	// setting timeout of recv setting
	setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO,(const char*)&tv_out, sizeof tv_out);
	// send icmp packet in an loop
	for(pingloop=0;pingloop<5;pingloop++)
	{
		
		flag=1;	
		
		bzero(&pckt, sizeof(pckt));		
		pckt.hdr.type = ICMP_ECHO;
		pckt.hdr.un.echo.id = getpid();		
		for ( i = 0; i < sizeof(pckt.msg)-1; i++ )
			pckt.msg[i] = i+'0';		
		pckt.msg[i] = 0;
		pckt.hdr.un.echo.sequence = msg_count++;
		pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));
		usleep(PING_SLEEP_RATE);
		//send packet
		clock_gettime(CLOCK_MONOTONIC, &time_start);
		if ( sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) <= 0) {
			printf("...Packet Sending Failed!...");
			flag=0;
		}
		//receive packet
		addr_len=sizeof(r_addr);
		if (recvfrom(ping_sockfd, &pckt, sizeof(pckt),0,(struct sockaddr*)&r_addr, &addr_len) <= 0 && msg_count>1)
		{
			printf("...Packet receive failed!...");
		}
        else
		{
			clock_gettime(CLOCK_MONOTONIC, &time_end);			
			double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec))/1000000.0 ;
            rtt_msec = (time_end.tv_sec- time_start.tv_sec) * 1000.0 + timeElapsed;			
			
			if(flag)
			{
				if(!(pckt.hdr.type ==69 && pckt.hdr.code==0))	{
					printf("..Error..Packet received with ICMP type %d code %d...", pckt.hdr.type, pckt.hdr.code);
				}
				else		{
					printf("%d bytes from %s (h: %s)(%s) msg_seq=%d ttl=%drtt = %Lf ms...", PING_PKT_S, ping_dom, rev_host,	ping_ip, msg_count, ttl_val, rtt_msec);
					msg_received_count++;
				}
			}
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &tfe);
	double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec))/1000000.0;	
	total_msec = (tfe.tv_sec-tfs.tv_sec)*1000.0 + timeElapsed;
					
	printf("=====%s ping statistics=====", ping_ip);
	printf("%d packets sent, %d packets received, %f percent packet loss. Total time: %Lf ms...", msg_count, msg_received_count,((msg_count - msg_received_count)/msg_count) * 100.0, total_msec);
}


int main(int argc, char *argv[])
{
	int sockfd;
	char *ip_addr, *reverse_hostname;
	struct sockaddr_in addr_con;
	int addrlen = sizeof(addr_con);
	char net_buf[NI_MAXHOST];

	if(argc!=2)	{
		printf("..Format %s <address>...", argv[0]);
		return 0;
	}

	ip_addr = dns_lookup(argv[1], &addr_con);
	if(ip_addr==NULL)	{
		printf("..DNS lookup failed! Could not resolve hostname!...");
		return 0;
	}

	reverse_hostname = reverse_dns_lookup(ip_addr);
	printf("===Trying to connect to '%s' IP: %s===",argv[1], ip_addr);
	printf("===Reverse Lookup domain: %s===", reverse_hostname);

	//socket()
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);//AF_INET is IPv4
	if(sockfd<0)	{
		printf("\nSocket file descriptor not received!!\n");
		return 0;
	}
	else
		printf("===Socket file descriptor %d received===", sockfd);
	signal(SIGINT, intHandler);             //catching interrupt

	
	send_ping(sockfd, &addr_con, reverse_hostname, ip_addr, argv[1]);
	
	return 0;
}
