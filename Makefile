CC      = g++
CFLAGS  = -g 
LDFLAGS = -lpthread  -lpcap 

all: nfshim  nfshim-pcap 

nfshim: nfshim.o PrintErrno.o demonizer.o
	$(CC) -o $@ $^ $(LDFLAGS)

nfshim-pcap: nfshim-libpcap.o PrintErrno.o demonizer.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONY: clean 

clean:
	rm *.o nfshim  nfshim-pcap

