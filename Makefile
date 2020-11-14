CC=gcc
CXX=g++
LDFLAGS=-lpcap -lpcre -lgps -lsqlite3 -lwiringPi
BINS=wscand exportKml test_gps
CXXFLAGS+=-g

OBJS=radiotap.o create_pid_file.o region_locking.o get_num.o error_functions.o database.o wscan.o gps_utils.o manufacturer.o string_utils.o heartbeat.o networkDiscovery.o

all: linux exportKml test_gps

Linux linux: $(OBJS)
	${CXX} -DLINUX $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $(OBJS) -o wscand

osx osX OSX FreeBSD freebsd: $(OBJS)
	${CXX} -DFREEBSD $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $(OBJS) -o wscand

exportKml: exportKml.o string_utils.o
	${CXX} $(CPPFLAGS) $(CXXFLAGS)  $(LDFLAGS) exportKml.o string_utils.o -o exportKml

test_gps: test_gps.o gps_utils.o
	${CXX} $(CPPFLAGS) $(CXXFLAGS)  $(LDFLAGS) test_gps.o gps_utils.o -o test_gps

install:
	cp wscand /usr/sbin
	cp scripts/wscand /etc/init.d
	chmod 0755 /etc/init.d/wscand

clean:
	rm -f a.out $(BINS) $(OBJS) exportKml.o test_gps.o
