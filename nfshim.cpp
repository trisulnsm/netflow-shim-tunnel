#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <regex>
#include <iostream>
#include "PrintErrno.h"
#include "demonizer.h"
#include <unistd.h>

using namespace std;

static const char * USAGESTR="Usage :  nfshim [-D] local-ip:local-port  receiver-ip:receiver-port [local-bind-ip] " ;


// nfshim  local-ip:local-port receiver-ip:receiver-port  local-ip-bind 
int main(int argc, char *argv[]) 
{
	bool fDaemonize=false;

	if (argc<2) {
		cerr << USAGESTR << endl ;
		return -1;
	}

	if (strcmp(argv[1],"-D")==0) {
		fDaemonize=true;
		--argc;
		++argv;
	}


	if (argc != 3  and argc != 4 ) {
		cerr << USAGESTR << endl ;
		return -1;
	}


	std::string localip, receiverip, localbindip;
	int 		localport, receiverport;

	const std::regex mRX( "([\\d\\.]+):(\\d+)");
	std::smatch mch;

	const std::string  lS(argv[1]);
	if ( not std::regex_match(lS, mch, mRX )) {
		cerr << "Error with local ip and port ip format " << argv[1] << endl;
		cerr << USAGESTR << endl ;
		return -1;
	}
	localip=mch[1];
	localport=std::stoi(mch[2]);


	const std::string  rS(argv[2]);
	if ( not std::regex_match( rS, mch, mRX )) {
		cerr << "Error with receiver ip and port ip format " << argv[2] << endl;
		cerr << USAGESTR << endl ;
		return -1;
	}
	receiverip=mch[1];
	receiverport=std::stoi(mch[2]);

	if (argc==4) {
		localbindip=argv[3];
	}


	// Server socket 
	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(localport);
	if ( localip=="0.0.0.0" ) {
		server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	} else  {
		inet_pton(AF_INET, localip.c_str(), &server_address.sin_addr);
	}

	int sock_local;
	if ((sock_local = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		CPrintErrno pe(errno);
		cerr << "Local socket create error=" << pe.what() << endl;
		return -1;
	}

	if ((bind(sock_local, (struct sockaddr *)&server_address,
	          sizeof(server_address))) < 0) {
		CPrintErrno pe(errno);
		cerr << "Local socket bind  error=" << pe.what() << endl;
		return -1;
	}


	// Receiver socket  
	struct sockaddr_in receiver_address;
	memset(&receiver_address, 0, sizeof(receiver_address));
	receiver_address.sin_family = AF_INET;
	receiver_address.sin_port = htons(receiverport);
	inet_pton(AF_INET, receiverip.c_str(), &receiver_address.sin_addr);

	int sock_receiver;
	if ((sock_receiver = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		CPrintErrno pe(errno);
		cerr << "Receiver socket create  error=" << pe.what() << endl;
		return 1;
	}


	// For binding receiver 
	if (not localbindip.empty()) {
		struct sockaddr_in rbind;
		memset(&rbind, 0, sizeof(rbind));
		rbind.sin_family = AF_INET;
		inet_pton(AF_INET, localbindip.c_str(), &rbind.sin_addr);

		if ((bind(sock_receiver, (struct sockaddr *)&rbind,
				  sizeof(rbind))) < 0) {
			CPrintErrno pe(errno);
			cerr << "Local recv bind  error=" << pe.what() << endl;
			return -1;
		}
		
		cout << "Bound to local IP for sending " << localbindip <<  endl << flush;
	}


	// The address to be used as a shim 
	struct sockaddr_in client_address;
	socklen_t  client_address_len = 0;

	// Daemonize 
	if (fDaemonize) {
		cout << "Going into background as a daemon.." << endl;
		daemonize();
		sleep(1);
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
		auto  len = recvfrom(sock_local, U.shim.buffer, sizeof(U.shim.buffer), 0,
		                   (struct sockaddr *)&client_address,
		                   &client_address_len);
		if (len == -1) {
			CPrintErrno pe(errno);
			cerr << "recvfrom() error =" << pe.what() << endl;
			return 1;
		}

		// shim the new ip 
		if (not fDaemonize) {
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

		if (not fDaemonize) {
			cout << "Forwarded  shimmed  bytes = " << slen << endl << flush;
		}

	}

	return 0;
}
