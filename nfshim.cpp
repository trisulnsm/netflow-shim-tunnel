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
#include <getopt.h>

using namespace std;

struct SOptions {

	using ipport_t  = std::pair<std::string, int>;
    bool fDaemonize;
    std::string localip;
    std::string localbindip;
    int localport;
    std::vector<ipport_t> receivers; // Changed to pair for IP and Port
};

static const char * USAGESTR="Usage :  nfshim [--daemonize] --from-ipport local-ip:local-port --to-ipport receiver-ip:receiver-port [--bind-address local-bind-ip] ";

int main(int argc, char *argv[]) 
{
    SOptions Sopt = {false, "", "", 0, {} }; // Updated initialization for receiver

    static struct option long_options[] = {
        {"daemonize", no_argument, 0, 'D'},
        {"from-ipport", required_argument, 0, 'f'},
        {"to-ipport", required_argument, 0, 't'},
        {"bind-address", required_argument, 0, 'b'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "Df:t:b:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'D':
                Sopt.fDaemonize = true;
                break;
            case 'f': {
                const std::regex mRX("([\\d\\.]+):(\\d+)");
                std::smatch mch;
                std::string lS(optarg);
                if (!std::regex_match(lS, mch, mRX)) {
                    cerr << "Error with local ip and port format: " << optarg << endl;
                    cerr << USAGESTR << endl;
                    return -1;
                }
                Sopt.localip = mch[1];
                Sopt.localport = std::stoi(mch[2]);
                break;
            }
            case 't': {
                const std::regex mRX("([\\d\\.]+):(\\d+)");
                std::smatch mch;
                std::string rS(optarg);
                if (!std::regex_match(rS, mch, mRX)) {
                    cerr << "Error with receiver ip and port format: " << optarg << endl;
                    cerr << USAGESTR << endl;
                    return -1;
                }

				SOptions::ipport_t  rec { mch[1], std::stoi(mch[2]) };
				Sopt.receivers.push_back(rec);
                break;
            }
            case 'b':
                Sopt.localbindip = optarg;
                break;
            default:
                cerr << USAGESTR << endl;
                return -1;
        }
    }

    if (Sopt.localip.empty() || Sopt.receivers.empty() || Sopt.localport == 0) {
        cerr << "Missing required options." << endl;
        cerr << USAGESTR << endl;
        return -1;
    }

    // Server socket 
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(Sopt.localport);
    if (Sopt.localip == "0.0.0.0") {
        server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        inet_pton(AF_INET, Sopt.localip.c_str(), &server_address.sin_addr);
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
	std::vector< struct sockaddr_in > receiver_addresses;
	std::vector<int> receiver_sockets;

	for (auto & ipport : Sopt.receivers) 
	{
		struct sockaddr_in receiver_address;
		memset(&receiver_address, 0, sizeof(receiver_address));
		receiver_address.sin_family = AF_INET;
		receiver_address.sin_port = htons(ipport.second);
		inet_pton(AF_INET, ipport.first.c_str(), &receiver_address.sin_addr);

		int sock_receiver;
		if ((sock_receiver = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
			CPrintErrno pe(errno);
			cerr << "Receiver socket create  error=" << pe.what() << endl;
			return 1;
		} 

		// For binding receiver 
		if (!Sopt.localbindip.empty()) {
			struct sockaddr_in rbind;
			memset(&rbind, 0, sizeof(rbind));
			rbind.sin_family = AF_INET;
			inet_pton(AF_INET, Sopt.localbindip.c_str(), &rbind.sin_addr);

			if ((bind(sock_receiver, (struct sockaddr *)&rbind,
					sizeof(rbind))) < 0) {
				CPrintErrno pe(errno);
				cerr << "Local recv bind  error=" << pe.what() << endl;
				return -1;
			}
			
			cout << "Bound to local IP for sending " << Sopt.localbindip <<  endl << flush;
		}

		receiver_addresses.push_back(receiver_address);
		receiver_sockets.push_back(sock_receiver);

	}
    // The address to be used as a shim 
    struct sockaddr_in client_address;
    socklen_t  client_address_len = 0;

    // Daemonize 
    if (Sopt.fDaemonize) {
        cout << "Going into background as a daemon.." << endl;
        daemonize();
        sleep(1);
    }

    // run indefinitely
    while (true) {
        union {
            struct {
                char     mark1[4];
                uint32_t shimip;
                char     mark2[4];
                char     buffer[16000-12];
            } shim;
            char     buffer[16000];
        } U;

        memcpy(U.shim.mark1, "TRIS", 4);
        memcpy(U.shim.mark2, "LNSM", 4);

        // netflow packets from routers 
        auto len = recvfrom(sock_local, U.shim.buffer, sizeof(U.shim.buffer), 0,
                            (struct sockaddr *)&client_address,
                            &client_address_len);
        if (len == -1) {
            CPrintErrno pe(errno);
            cerr << "recvfrom() error =" << pe.what() << endl;
            return 1;
        }

        // shim the new ip 
        if (!Sopt.fDaemonize) {
            cout << "Router " << inet_ntoa(client_address.sin_addr) << " bytes = " << len << endl << flush; 
        }

        U.shim.shimip = client_address.sin_addr.s_addr;

        // send the shimmed to receiver  
		for (size_t i = 0; i < receiver_sockets.size(); ++i) 
		{
			int sock_receiver = receiver_sockets[i];
			struct sockaddr_in & receiver_address = receiver_addresses[i];	

			auto slen = sendto(sock_receiver, U.buffer, len + 12, 0,
							(struct sockaddr*) &receiver_address, sizeof(receiver_address));

			if (slen == -1) {
				CPrintErrno pe(errno);
				cerr << "sendto() error =" << pe.what() << endl;
				return 1;
			}

			if (!Sopt.fDaemonize) {
				cout << "Forwarded  shimmed  bytes [" << i << "] len= " << slen << endl << flush;
			}

		}
    }

    return 0;
}
