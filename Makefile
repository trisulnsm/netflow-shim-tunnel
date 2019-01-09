CC      = g++
CFLAGS  = -g -std=c++0x
LDFLAGS = -lpthread -lre2 

all: nfshim 

nfshim: nfshim.o PrintErrno.o demonizer.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONY: clean 

clean:
	rm *.o nfshim 

