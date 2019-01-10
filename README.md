# netflow-shim-tunnel

Accepts Netflow from multiple routers relays it to a receiver as a shim tunnel.

## Use case

Relaying netflow to a remote Trisul without using NAT GRE or VPN tunneling.
This daemon adds a 12 byte shim header before the Netflow header. 



## On the gateway run the shim software

Download the binary for your platform from the binaries directory


### Usage 


To forward from local-port to remote trisul-ip and trisul-port. The -D puts it into daemon mode


````
nfshim [-D]  local-ip:local-port  trisul-ip:trisul-port 
````

For example , download the nfshim.el7 binary and run

To forward all netflow traffic on gateway on port 2055 to Trisul running on 192.168.2.99. 

````
nfshim.el7 -D 0.0.0.0:2055 192.168.2.99:2055
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

