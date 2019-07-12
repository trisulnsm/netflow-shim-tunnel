CC      = g++
CFLAGS  = -g -std=c++0x
LDFLAGS = -lpthread -lre2  -lpcap 

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

