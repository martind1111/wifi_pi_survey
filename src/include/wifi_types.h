#ifndef _WIFI_TYPES_H
#define _WIFI_TYPES_H

#define RT_VERSION_LEN 1
#define RT_LENGTH_LEN 2

typedef struct mac_header{
  unsigned char fc[2];
  unsigned char id[2];
  struct ether_addr addr1;
  struct ether_addr addr2;
  struct ether_addr addr3;
  unsigned char sc[2];
} mac_header;

typedef struct frame_control {
  unsigned protocol : 2;
  unsigned type : 2;
  unsigned subtype : 4;
  unsigned to_ds : 1;
  unsigned from_ds : 1;
  unsigned more_frag : 1;
  unsigned retry : 1;
  unsigned pwr_mgt : 1;
  unsigned more_data : 1;
  unsigned wep : 1;
  unsigned order : 1;
} frame_control;

#endif // _WIFI_TYPES_H
