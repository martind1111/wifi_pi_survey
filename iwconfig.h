#ifndef _IWCONFIG_H
#define _IWCONFIG_H

typedef struct iw_freq iwfreq;

int sockets_open(void);

int iwconfig_open();

void float2freq(double in, iwfreq *out);

int freq2channel(uint16_t freq);

int setChannel(char *ifName, int channel);

void iwconfig_close();

#endif // _IWCONFIG_H
