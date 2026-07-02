#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <regex>
#include <iostream>
#include <set>
#include <sstream>
#include "PrintErrno.h"
#include "demonizer.h"
#include <unistd.h>
#include <getopt.h>

using namespace std;

enum class EIpFilterMode { None, Include, Exclude };

struct SOptions {

	using ipport_t  = std::pair<std::string, int>;
    bool fDaemonize;
    bool fDebug;
    bool fRoundRobin;
    std::string localip;
    std::string localbindip;
    int localport;
    std::vector<ipport_t> receivers; // Changed to pair for IP and Port
    EIpFilterMode ipFilterMode;      // filter on the source (router) IP
    std::set<uint32_t> ipFilterSet;  // IPs stored in network byte order
};

static const char * USAGESTR="Usage :  nfshim [--daemonize] [--debug] [-R] --from-ipport local-ip:local-port --to-ipport receiver-ip:receiver-port [--bind-address local-bind-ip] [--include-ip-list ip1,ip2,..  |  --exclude-ip-list ip1,ip2,..] ";

// Parse a comma separated list of IPv4 addresses into a set of addresses
// stored in network byte order. Returns false on any malformed address.
static bool ParseIpList(const std::string & list, std::set<uint32_t> & out)
{
    std::stringstream ss(list);
    std::string token;
    while (std::getline(ss, token, ',')) {
        // trim surrounding whitespace
        size_t b = token.find_first_not_of(" \t");
        size_t e = token.find_last_not_of(" \t");
        if (b == std::string::npos) {
            continue; // skip empty entries
        }
        token = token.substr(b, e - b + 1);

        struct in_addr addr;
        if (inet_pton(AF_INET, token.c_str(), &addr) != 1) {
            cerr << "Invalid IPv4 address in ip list: " << token << endl;
            return false;
        }
        out.insert(addr.s_addr);
    }
    return true;
}

int main(int argc, char *argv[]) 
{
    SOptions Sopt = {false, false, false, "", "", 0, {}, EIpFilterMode::None, {} };

    static struct option long_options[] = {
        {"daemonize", no_argument, 0, 'D'},
        {"debug", no_argument, 0, 'v'},
        {"round-robin", no_argument, 0, 'R'},
        {"from-ipport", required_argument, 0, 'f'},
        {"to-ipport", required_argument, 0, 't'},
        {"bind-address", required_argument, 0, 'b'},
        {"include-ip-list", required_argument, 0, 'I'},
        {"exclude-ip-list", required_argument, 0, 'E'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "DvRf:t:b:I:E:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'D':
                Sopt.fDaemonize = true;
                break;
            case 'v':
                Sopt.fDebug = true;
                break;
            case 'R':
                Sopt.fRoundRobin = true;
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
            case 'I': {
                if (Sopt.ipFilterMode != EIpFilterMode::None) {
                    cerr << "Cannot use --include-ip-list together with --exclude-ip-list." << endl;
                    cerr << USAGESTR << endl;
                    return -1;
                }
                if (!ParseIpList(optarg, Sopt.ipFilterSet)) {
                    cerr << USAGESTR << endl;
                    return -1;
                }
                Sopt.ipFilterMode = EIpFilterMode::Include;
                break;
            }
            case 'E': {
                if (Sopt.ipFilterMode != EIpFilterMode::None) {
                    cerr << "Cannot use --exclude-ip-list together with --include-ip-list." << endl;
                    cerr << USAGESTR << endl;
                    return -1;
                }
                if (!ParseIpList(optarg, Sopt.ipFilterSet)) {
                    cerr << USAGESTR << endl;
                    return -1;
                }
                Sopt.ipFilterMode = EIpFilterMode::Exclude;
                break;
            }
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

    // Debug logging is meaningless once we detach from the terminal, so it is
    // always disabled in daemon mode regardless of --debug.
    if (Sopt.fDaemonize) {
        Sopt.fDebug = false;
    }

    if (Sopt.ipFilterMode != EIpFilterMode::None && Sopt.ipFilterSet.empty()) {
        cerr << "Empty ip list supplied to --include-ip-list/--exclude-ip-list." << endl;
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

    // Netflow arrives in bursts from many routers. While we are busy in
    // sendto() the kernel keeps queuing incoming datagrams in this socket's
    // receive buffer; if it fills up the kernel silently drops packets. Ask
    // for a large receive buffer to absorb the bursts. SO_RCVBUF is capped by
    // net.core.rmem_max; SO_RCVBUFFORCE (root only) bypasses that cap.
    {
        const int desired = 32 * 1024 * 1024; // 32 MiB
        if (setsockopt(sock_local, SOL_SOCKET, SO_RCVBUFFORCE, &desired, sizeof(desired)) < 0) {
            // Fall back to the normal (rmem_max-capped) request when not root.
            if (setsockopt(sock_local, SOL_SOCKET, SO_RCVBUF, &desired, sizeof(desired)) < 0) {
                CPrintErrno pe(errno);
                cerr << "Warning: could not set SO_RCVBUF: " << pe.what() << endl;
            }
        }
        if (Sopt.fDebug) {
            int actual = 0;
            socklen_t optlen = sizeof(actual);
            if (getsockopt(sock_local, SOL_SOCKET, SO_RCVBUF, &actual, &optlen) == 0) {
                // The kernel reports double the usable size (bookkeeping overhead).
                cout << "Local socket receive buffer = " << actual << " bytes" << endl << flush;
            }
        }
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
    socklen_t  client_address_len = sizeof(client_address);

    // Daemonize 
    if (Sopt.fDaemonize) {
        cout << "Going into background as a daemon.." << endl;
        daemonize();
        sleep(1);
    }

    size_t round_robin_idx = 0;

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
        if (Sopt.fDebug) {
            cout << "Router " << inet_ntoa(client_address.sin_addr) << " bytes = " << len << endl << flush; 
        }

        // Filter on the source (router) IP if a filter list was supplied.
        if (Sopt.ipFilterMode != EIpFilterMode::None) {
            const bool inList = Sopt.ipFilterSet.count(client_address.sin_addr.s_addr) > 0;
            const bool allow  = (Sopt.ipFilterMode == EIpFilterMode::Include) ? inList : !inList;
            if (!allow) {
                if (Sopt.fDebug) {
                    cout << "Dropped (ip filter) router " << inet_ntoa(client_address.sin_addr) << endl << flush;
                }
                continue;
            }
        }

        U.shim.shimip = client_address.sin_addr.s_addr;

        // send the shimmed to receiver(s)
		const size_t n_receivers = receiver_sockets.size();
		const size_t send_begin = Sopt.fRoundRobin ? round_robin_idx : 0;
		const size_t send_end = Sopt.fRoundRobin ? send_begin + 1 : n_receivers;

		if (Sopt.fRoundRobin) {
			round_robin_idx = (round_robin_idx + 1) % n_receivers;
		}

		for (size_t i = send_begin; i < send_end; ++i)
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

			if (Sopt.fDebug) {
				cout << "Forwarded  shimmed  bytes [" << i << "] len= " << slen << endl << flush;
			}

		}
    }

    return 0;
}
