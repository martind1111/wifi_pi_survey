#ifndef _PACKET_H
#define _PACKET_H

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

struct pcap_pkthdr;

struct Packet {
    Packet(const pcap_pkthdr* pkthdr, const uint8_t* packet_data);

    const uint8_t* GetData() const { return data; }
    size_t GetLength() const { return length; }
    size_t GetCaptureLength() const { return capture_length; }
    struct timeval GetTimestamp() const { return timestamp; }

private:
    const uint8_t* data;
    size_t length;
    size_t capture_length;
    struct timeval timestamp;
};

#endif // _PACKET_H
