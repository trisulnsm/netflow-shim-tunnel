#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <fstream>
#include <iostream>
#include "PrintErrno.h"
#include "demonizer.h"
#include <unistd.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <pwd.h>

using namespace std;

static const char * USAGESTR="Usage :  nfshim-pcap [-D] -i interface-name  [-f capture-expression]  --destination-ip  receiver-ip --destination-port receiver-port [--local-bind-ip ip-address] [-u username]  [--pid-file file]" ;

#define  HPTRVAL_USHORT(p)   (ntohs(*((unsigned short *)(p) )))

pcap_t  * 		setup_pcap( const std::string& interface_name,  const std::string& filter);
int  pcap_recvfrom(pcap_t * pcap_fd , char * outbuf , size_t outbuf_sz, struct sockaddr_in * client_ip);


/* IP header */
typedef struct ip_header{
	uint8_t	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	uint8_t	tos;			// Type of service 
	uint16_t	tlen;			// Total length 
	uint16_t  identifier;     // Identification
	uint16_t  flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	uint8_t	ttl;			// Time to live
	uint8_t	proto;			// Protocol
	uint16_t  crc;			// Header checksum
	uint32_t	saddr;		    // Source address
	uint32_t	daddr;		    // Destination address
	uint8_t 	op_pad[4];		// Option + Padding
}ip_header;

// nfshim  local-ip:local-port receiver-ip:receiver-port  local-ip-bind 
int main(int argc, char *argv[]) 
{
	struct {
		bool    		fDaemonize=false;
		std::string		interface;
		std::string		filter;
		std::string		receiver_ip;
		int				receiver_port=0;
		std::string		local_bind_ip;
		std::string     user;
		std::string     pidfile;

	} cmd_opts;

    const char* const 	short_opts = "Di:f:d:p:l:u:";
    const option 		long_opts[] = {
            {"daemonize",   		no_argument, 		nullptr, 'D'},
            {"interface", 			required_argument, 	nullptr, 'i'},
            {"filter", 				required_argument, 	nullptr, 'f'},
            {"destination-ip", 		required_argument, 	nullptr, 'd'},
            {"destination-port", 	required_argument, 	nullptr, 'p'},
            {"local-bind-ip", 		required_argument, 	nullptr, 'l'},
            {"user", 				required_argument, 	nullptr, 'u'},
            {"pid-file", 			required_argument,  nullptr, 'I'},

    };

    while (true)
    {
        const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);

        if (-1 == opt)
            break;

        switch (opt)
        {
			case 'D':
				cmd_opts.fDaemonize = true;
				break;

			case 'i':
				cmd_opts.interface = std::string(optarg);
				break;

			case 'u':
				cmd_opts.user = std::string(optarg);
				break;


			case 'f':
				cmd_opts.filter = std::string(optarg);
				break;

			case 'd':
				cmd_opts.receiver_ip = std::string(optarg);
				break;

			case 'I':
				cmd_opts.pidfile = std::string(optarg);
				break;

			case 'p':
				{
					cmd_opts.receiver_port=std::stoi( std::string(optarg));
				}
				break;

			case 'l':
				cmd_opts.local_bind_ip = std::string(optarg);
				break;

			case 'h': // -h or --help
			case '?': // Unrecognized option
			default:
				cerr << USAGESTR << endl;
				return -1;
		}
    }


	// check
	if ( cmd_opts.interface.empty() or
		 cmd_opts.receiver_ip.empty() or
		 cmd_opts.receiver_port == 0)
    {
		cerr << USAGESTR << endl;
		return -1;
	}


	// Open pcap 
	pcap_t  *  pcap_handle=setup_pcap( cmd_opts.interface.c_str(), cmd_opts.filter.c_str());
	if (pcap_handle==nullptr) {
		cerr << "Unable to open the capture interface due to previous error" << endl;
		return -1;
	}


	// Drop privs if user supplied 
	if (not cmd_opts.user.empty()) {
		cout << "Pcap open success, dropping privileges to " << cmd_opts.user << endl;

	   // Attempt to switch over to the privdrop user 
	   struct passwd *pw = getpwnam(cmd_opts.user.c_str());
	   if (pw == NULL) 
	   {
	   		cerr << "invalid user " << cmd_opts.user << endl;
			return -1;

	   }

	   // Ok, now set the gid and uid of the process
	   if (setgid(pw->pw_gid) == -1)
	   {
	   		cerr << "error in setgid" << endl;
			return -1;
	   }
	   if (setuid(pw->pw_uid) == -1)
	   {
	   		cerr << "error in setuid" << endl;
			return -1;
	   }
	}


	// Receiver socket  
	struct sockaddr_in receiver_address;
	memset(&receiver_address, 0, sizeof(receiver_address));
	receiver_address.sin_family = AF_INET;
	receiver_address.sin_port = htons(cmd_opts.receiver_port);
	inet_pton(AF_INET, cmd_opts.receiver_ip.c_str(), &receiver_address.sin_addr);

	int sock_receiver;
	if ((sock_receiver = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		CPrintErrno pe(errno);
		cerr << "Receiver socket create  error=" << pe.what() << endl;
		return 1;
	}


	// For binding receiver 
	if (not cmd_opts.local_bind_ip.empty()) {
		struct sockaddr_in rbind;
		memset(&rbind, 0, sizeof(rbind));
		rbind.sin_family = AF_INET;
		inet_pton(AF_INET, cmd_opts.local_bind_ip.c_str(), &rbind.sin_addr);

		if ((bind(sock_receiver, (struct sockaddr *)&rbind,
				  sizeof(rbind))) < 0) {
			CPrintErrno pe(errno);
			cerr << "Local recv bind  error=" << pe.what() << endl;
			return -1;
		}
		
		cout << "Bound to local IP for sending " << cmd_opts.local_bind_ip <<  endl << flush;
	}


	// The address to be used as a shim 
	struct sockaddr_in client_address;
	socklen_t  client_address_len = 0;

	// Daemonize 
	if (cmd_opts.fDaemonize) {
		cout << "Going into background as a daemon.." << endl;
		daemonize();
		sleep(1);
	}


	// PID file
	if (not cmd_opts.pidfile.empty()) {
		
		std::ofstream pidfile(cmd_opts.pidfile.c_str(), std::ios::out | std::ios::binary );
		if (pidfile.good())
		{
			pidfile << std::to_string(getpid());
			pidfile.close();
		} 
		else
		{
			CPrintErrno pe(errno);
			cerr << "warning: Unable to write pidfile " << cmd_opts.pidfile << " err=" << pe.what() << endl;
		}
	}
	

	// run indefinitely
	while (true) {
		union {
			struct {
				char 	 mark1[4];
				uint32_t shimip;
				char     mark2[4];
				char     buffer[16000-12];
			} shim;
			char     buffer[16000];
		} U;

		memcpy(U.shim.mark1,"TRIS",4);
		memcpy(U.shim.mark2,"LNSM",4);


		// netflow packets from routers 
		auto  len = pcap_recvfrom(pcap_handle, U.shim.buffer, sizeof(U.shim.buffer), &client_address);
		if (len == -1) {
			CPrintErrno pe(errno);
			cerr << "recvfrom() error =" << pe.what() << endl;
			return 1;
		}

		if (len==0) {
			continue;
		}

		// shim the new ip 
		if (not cmd_opts.fDaemonize) {
			cout << "Router " << inet_ntoa(client_address.sin_addr) << " bytes = " << len << endl << flush; 
		}

		U.shim.shimip=client_address.sin_addr.s_addr;

		// send the shimmed to receiver  
		auto  slen = sendto(sock_receiver, U.buffer, len+12, 0,
						(struct sockaddr*) & receiver_address, sizeof(receiver_address));

		if (slen == -1) {
			CPrintErrno pe(errno);
			cerr << "sendto() error =" << pe.what() << endl ;
			return 1;
		}

		if (not cmd_opts.fDaemonize) {
			cout << "Forwarded  shimmed  bytes = " << slen << endl << flush;
		}

	}

	return 0;
}



pcap_t  * 		setup_pcap( const std::string& interface_name,  const std::string& filter)
{

    char 	errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;        /* to hold compiled program */
    char dev_buff[64] = {0};
    int i =0;


    // Now, open device for sniffing
    pcap * fd_ret  = pcap_open_live(interface_name.c_str(), 65536, 1,1000, errbuf);
    if(fd_ret  == nullptr)
    {
        cerr <<  "pcap_open_live() failed due to " <<  errbuf << endl;
        return nullptr;
    }

	
	if ( filter.length() > 0 ) {
		// Compile the filter expression
		if(pcap_compile(fd_ret, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
		{
			cerr <<  "pcap_compile() failed for [" <<  filter << "] err=" << pcap_geterr(fd_ret) << endl;
			return nullptr;
		}

		// Set the filter compiled above
		if(pcap_setfilter(fd_ret, &fp) == -1)
		{
			CPrintErrno pe(errno);
			cerr <<  "pcap_setfilter() failed for [" <<  filter << "] err=" << pe.what() << endl;
			return nullptr;
		}
	}

	return fd_ret;
}

int  pcap_recvfrom(pcap_t * pcap_fd , char * outbuf , size_t outbuf_sz, struct sockaddr_in * client_ip)
{

	struct pcap_pkthdr    * pc_header;
	const uint8_t         * pData;

	int ret = pcap_next_ex(pcap_fd, &pc_header,  & pData);
	if (ret==-1) {
		cerr <<  "pcap_next_ex() failed err=" << pcap_geterr(pcap_fd) << endl;
		return -1;
	} else if (ret==0) {
		return 0;
	} else {

		/* Only IP, check ethertypes gets thru */
		const uint8_t         * pIPData;
		switch (pcap_datalink(pcap_fd))
		{
			case DLT_RAW: 
			case 101: /* DLT_101 */
				pIPData = pData + 0;
				break;

			case DLT_LINUX_SLL:
				if (HPTRVAL_USHORT(pData+14)!=0x0800) return 0;
				pIPData = pData + 16;
				break;

			default:
				{
				  switch (HPTRVAL_USHORT(pData+12))
				  {
					case 0x0800: 
						pIPData = pData + 14;
						break;                 // normal Ethernet nothing to do 

					case 0x8847:
						if (HPTRVAL_USHORT(pData+17)&0x01) {
							pIPData = pData + 18;
						} else if (HPTRVAL_USHORT(pData+21)&0x01) {
							pIPData = pData + 22;
						} else if (HPTRVAL_USHORT(pData+25)&0x01) {
							pIPData = pData + 26;
						} else if (HPTRVAL_USHORT(pData+29)&0x01) {
							pIPData = pData + 30;
						} else {
							return 0;
						}
						break;


					case 0x8100: 
						// only support 2 tags 
						if (HPTRVAL_USHORT(pData+16)==0x0800)
							pIPData = pData + 18;
						else if (HPTRVAL_USHORT(pData+16)==0x8100 &&
								 HPTRVAL_USHORT(pData+20)==0x0800)
							pIPData = pData + 22;
						else
							return 0;
						break;			       // 802.1Q skip VLAN TAGs

					default:
						return 0;	       // unsupported Ethertype 
					}

				}
				break;
		}

		const ip_header * pIPH = (const ip_header*) pIPData;

		// only UDP 
		if (pIPH->proto!=17)
			return 0;

		const uint8_t * pPayload = pIPData + 4*(pIPH->ver_ihl& 0x0F) + 8;

		client_ip->sin_addr.s_addr=pIPH->saddr;

		int  paylen = pc_header->caplen - (pPayload-pData);
		memcpy(outbuf, pPayload, paylen);

		return paylen;
	}

}
