# netflow-shim-tunnel

> NEW 11-JUL-2019 :   A new nfshim-pcap tool that can read netflow directly from the interface using
>                     libpcap and forward via a UDP SHIM tunnel to a trisul server.

This repo contains two programs that can relay UDP packets from one interface to another by putting them inside a "shim tunnel"

* `nfshim` :  opens a normal UDP port listening on a particular port, then putting them into a tunnel and sending them to one or more target IPs.
* `nfshim-pcap` :  uses libpcap to directly sniff UDP packets matching a particular filter, and send them out through a tunnel to a target IP.

### Diagram of shim tunnel

This nfshim daemon adds a 12 byte shim header before the Netflow header. 

![shimtunnel](nfshim.png)

### Primary use case : Accepts Netflow from multiple routers relays it to one or more receivers as a shim tunnel.

Normally such a scenario will be supported by GRE tunnels. but some highly secure environments do not allow GRE. 

For more information [Why use a nfshim tunnel](https://www.trisul.org/devzone/doku.php/hardware:shimtunnelintro)

## Usage  nfshim 

> Download the binary for your platform from the binaries directory

To forward from local-port to one or more remote trisul-ip and trisul-port. The -D puts it into daemon mode.

````
nfshim [-D] --from-ipport local-ip:local-port --to-ipport receiver-ip:receiver-port [--to-ipport receiver-ip:receiver-port ...] [--bind-address local-ip-for-sending]
````

#### Options

  1.  `-D` or `--daemonize` :  send into background as daemon
  2.  `-f` or `--from-ipport` : specify the local IP and port in the format `local-ip:local-port`
  3.  `-t` or `--to-ipport` : specify the receiver IP and port in the format `receiver-ip:receiver-port`. This option can be specified multiple times to add multiple targets.
  4.  `-b` or `--bind-address` : optional - bind to a valid local IP address. Packets sent to the receivers will have this IP address.

### Examples 

#### To forward all netflow traffic on gateway on port 2055 to Trisul running on 192.168.2.99:2055. 

````
nfshim.el7 -D --from-ipport 0.0.0.0:2055 --to-ipport 192.168.2.99:2055
````

#### To forward all traffic to multiple receivers, binding 192.168.2.76 as the source IP for sending. 192.168.2.76 must be a valid IP on the server.

````
nfshim.el7 -D --from-ipport 0.0.0.0:2055 --to-ipport 192.168.2.99:2055 --to-ipport 192.168.2.100:2055 --bind-address 192.168.2.76
````

## Usage  nfshim-pcap

> Download the binary for your platform from the binaries directory

This program uses libpcap to capture the UDP packets from one side, pack it into the SHIM tunnel, then send it out the other.

````
nfshim-pcap [-D] -i interface-name  [-f capture-expression]  --destination-ip  receiver-ip --destination-port receiver-port [--local-bind-ip ip-address] [-u username]  [--pid-file file]
````

#### Options

  1.  `-D` :  send into background as daemon
  2.  `-i intf` :  capture from this interface 
  3.  `-f filter` :  optional- libpcap capture filter , eg 'udp port 2055' to select packets
  4.  `-d dest-ip` :  where to send the output packets  to
  4.  `-p dest-port` :  UDP Port for destination 
  4.  `-l local-ip` :  optional- use this IP as the source IP of the tunneled packets
  4.  `-u username` :  optional- drop privs to this user
  4.  `--pid-file file` :  optional- write the PID to this file 

### Examples 

#### To forward all netflow traffic on eth0 and output to 192.168.2.75 port  2055

````
nfshim-pcap -D -i eth0 -f 'udp port 2055'  -d 192.168.2.75 -p 2055 -u nobody --pid-file /tmp/shim.pid 
````

## On the Trisul-Probe side enable Shim

Edit the netflow config file 

```

/usr/local/share/trisul-probe/cfgedit

select Netflow 

```

Set EnableShimTunnel to TRUE 

````xml
<EnableShimTunnel>True</EnableShimTunnel>
````

Restart

