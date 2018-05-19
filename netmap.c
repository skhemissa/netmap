#include <stdio.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <sqlite3.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>

/***
Fast pcap data insertion into database

writtend by Sabri Khemissa sabri.khemissa[at]gmail.com

Only TCP packets are inserted into the database

Prerequisites:
	libpcap-dev
	libsqlite3-dev

Compilation command:
	cc -o netmap netmap.c -l pcap -l sqlite3

***/

// Globale variable for pcap
#define SIZE_ETHERNET 14

#define IPv4_ETHERTYPE 0x800

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)


#define BUFFER_SIZE 256

// Ethernet header
struct sniff_ethernet {
	u_char          ether_dhost[ETHER_ADDR_LEN];	/* Destination host address */
	u_char          ether_shost[ETHER_ADDR_LEN];	/* Source host address */
	u_short         ether_type;	/* IP? ARP? RARP? etc */
};

// IP header 
struct sniff_ip {
	u_char          ip_vhl;	/* version << 4 | header length >> 2 */
	u_char          ip_tos;	/* type of service */
	u_short         ip_len;	/* total length */
	u_short         ip_id;	/* identification */
	u_short         ip_off;	/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char          ip_ttl;	/* time to live */
	u_char          ip_p;	/* protocol */
	u_short         ip_sum;	/* checksum */
	struct in_addr  ip_src, ip_dst;	/* source and dest address */
};

// TCP header
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

int main(int argc, char *argv[])
{
	// start time 
	time_t begin = time(NULL);

	//database variables
        sqlite3 *db;
	sqlite3_stmt *stmt;
        char *zErrMsg = 0;
	char *tail = 0;
        int rc_create;
	int rc_insert;
	char *err_msg = 0;
        char *sql_create;
        char date_file[20];

	//time variables
        time_t t = time(NULL);
        struct tm tm = *localtime(&t);
	
	//pcap variables
	char *filename, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	const u_char *packet;
	struct pcap_pkthdr header;
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp; 
	char timestamp[100];
	u_char *ptr;
	u_int size_ip;

	//others variables
	int i;
	int k;
	char buf[80];
	int count = 0;
	int count_current = 0;
	float progress;

	//verify that the pcap file has been giving as argument
	if (argc < 2) {
		fprintf(stderr, "Incorrect number of arguments provided\n");
		fprintf(stderr, "Usage: readfile filename\n");
		return (2);
	}
	// opening the pcap file
	filename = argv[1];
	handle = pcap_open_offline(filename, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open file %s: %s\n", filename, errbuf);
		return (2);
	}

	// count the number if pcap lines to process, could be deleted if the displaying the progress of processing the pcap file isn't mandatory
	puts ("Calculating the number of pcap lines to process");
	for (i = 0; (packet = pcap_next(handle,&header)) != NULL; i++){
		count++;
	}
	puts("");
	puts("--");
	puts(""); 
	printf("Total lines to process: %d\n",count);
	puts ("");
	pcap_close(handle);


	handle = pcap_open_offline(filename, errbuf);	

	/*** Preparing the db file name that compose the sqlit3 db name***/
	sprintf(date_file, 
		"%d.%02d.%02d-%02d:%02d:%02d.db",
		tm.tm_year + 1900,
		tm.tm_mon + 1,
		tm.tm_mday,
		tm.tm_hour,
		tm.tm_min,
		tm.tm_sec);

	/*** Opening the db for creating the table, the db is created automaticly it not exist ***/
	sqlite3_open(date_file, &db);

        sql_create = "CREATE TABLE CAPTURE("  \
         "ID INTEGER PRIMARY KEY AUTOINCREMENT," \
         "TS CHAR(50) NOT NULL," \
         "IPSRC CHAR(15) NOT NULL," \
	 "MACSRC CHAR(20) NOT NULL,"
         "IPDST CHAR(15) NOT NULL," \
	 "MACDST CHAR(20) NOT NULL,"\
         "PORTDST INT NOT NULL,"\
	 //"TYPEPROTO CHAR(5) NOT NULL);";
	 "TYPEPROTO INT NOT NULL);";
	
	rc_create = sqlite3_exec(db, sql_create, 0, 0, &err_msg);	

	if (rc_create != SQLITE_OK ) {
        
        	fprintf(stderr, "SQL error: %s\n", err_msg);
        
        	sqlite3_free(err_msg);        
        	sqlite3_close(db);
        
        	return 1;
    	} 
	
	if (sqlite3_prepare_v2(db, 
			"INSERT INTO CAPTURE VALUES (NULL, ?, ?, ?, ?, ?, ?,?)", 
			-1,
			&stmt,
			0)
			!= SQLITE_OK) {
				printf("\nCould not prepare statement.\n");
    				return 1;
				}
	//Transaction usages increase wrinting performance ;-)
	sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, &zErrMsg);

	/*** Processing pcap file line by line ***/
	for (i = 0; (packet = pcap_next(handle,&header)) != NULL; i++){
		count_current++;
		fflush(stdout);
		ethernet = (struct sniff_ethernet*) (packet);
         	if (ntohs(ethernet->ether_type) == IPv4_ETHERTYPE) {
			ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
			size_ip = IP_HL(ip) * 4;
			if (IP_V(ip) == 4) {
				tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
				sprintf(timestamp,"%d",header.ts);

				//preparing the SQL statement	
			    	//sqlite3_bind_text(stmt, 1, timestamp, -1, SQLITE_TRANSIENT); 
			    	sqlite3_bind_text(stmt, 1, timestamp, -1, SQLITE_TRANSIENT); 
				sqlite3_bind_text(stmt, 2, inet_ntoa(ip->ip_src), -1, SQLITE_TRANSIENT);   
  				sqlite3_bind_text(stmt, 3, ether_ntoa(ethernet->ether_shost), -1, SQLITE_TRANSIENT);  
    				sqlite3_bind_text(stmt, 4, inet_ntoa(ip->ip_dst), -1, SQLITE_TRANSIENT); 
    				sqlite3_bind_text(stmt, 5, ether_ntoa(ethernet->ether_dhost), -1, SQLITE_TRANSIENT);   
    				sqlite3_bind_int(stmt, 6, ntohs(tcp->th_dport));  
    				sqlite3_bind_int(stmt, 7, ip->ip_p); 
				
				//executing the SQL statement
				rc_insert = sqlite3_step(stmt);
				if (rc_insert != SQLITE_DONE) {
            		   		printf("execution failed: %s", sqlite3_errmsg(db));
    				}	
    				sqlite3_clear_bindings(stmt);
    				sqlite3_reset(stmt);
				//}

			}
	        }
		//progress = (float)count_current / count * 100.0;
		//printf("Processed: %.1f%, %d lines of %d \r", progress, count_current, count);
	
	}
	puts("");
	puts("");

	printf("Database file: %s\n", date_file);

	puts("");
	puts("");
	puts("");
	
	// Closing the database
	sqlite3_exec(db, "END TRANSACTION", NULL, NULL, &zErrMsg);
	sqlite3_close(db);
	
	// Closing the pcap file
	pcap_close(handle);

	// print execution duration
	time_t end = time(NULL);
	printf("Elapsed: %d secondes\n", (end - begin) );

	return (0);
}
