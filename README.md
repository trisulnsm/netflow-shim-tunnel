# netflow-shim-tunnel

Accepts Netflow from multiple routers relays it to a receiver as a shim tunnel.

## Use case

Relaying netflow to a remote Trisul without using NAT GRE or VPN tunneling.
This daemon adds a 12 byte shim header before the Netflow header. 



## Using


````
nfshim [-D]  local-ip:local-port  trisul-ip:trisul-port 
````


On the Trisul-Probe side add the following Netflow parameter


/usr/local/share/trisul-probe/cfgedit

select Netflow 

````
<EnableShimTunnel>True</EnableShimTunnel>
````



