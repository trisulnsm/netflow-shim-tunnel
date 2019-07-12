# netflow-shim-tunnel

Accepts Netflow from multiple routers relays it to a receiver as a shim tunnel.


## Use case 
Tunnel  NETFLOW/SFLOW from routers in a DMZ to an internal Security Zone where Trisul NetworK Analytics is running. 
Relaying netflow to a remote Trisul without using NAT GRE or VPN tunneling.

This daemon adds a 12 byte shim header before the Netflow header. 

>> NEW 11-JUL-2019 :   A new nfshim-pcap tool that can read netflow directly from the interface using
>>                     libpcap and forward via a UDP SHIM tunnel to a trisul server.


## On the gateway run the shim software

Download the binary for your platform from the binaries directory


### Usage 

To forward from local-port to remote trisul-ip and trisul-port. The -D puts it into daemon mode


````
nfshim [-D]  local-ip:local-port  trisul-ip:trisul-port  [local-ip-for-sending]
````

#### Options

  1.  `-D` :  send into background as daemon
  2.  `local-ip-for-sending` : bind to a valid local IP address packets sent to trisul  will have this ip address 

### Examples 

#### To forward all netflow traffic on gateway on port 2055 to Trisul running on 192.168.2.99. 

````
nfshim.el7 -D 0.0.0.0:2055 192.168.2.99:2055
````

#### To forward all traffic binding  192.168.2.76  as the source IP for sending. 192.168.2.76 must be a valid IP on the server 

````
nfshim.el7 -D 0.0.0.0:2055 192.168.2.99:2055 192.168.2.76
````

## On the Trisul-Probe side enable Shim


Edit the netflow config file 

````
/usr/local/share/trisul-probe/cfgedit

select Netflow 

````

Set EnableShimTunnel to TRUE 

````xml
<EnableShimTunnel>True</EnableShimTunnel>
````


Restart 

