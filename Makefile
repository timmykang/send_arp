all: send_arp

send_arp: main.o
	g++ -o send_arp main.o -lpcap

main.o: main.cpp send.h
	g++ -c -o main.o main.cpp

clean:
	rm -f send_arp *.o
