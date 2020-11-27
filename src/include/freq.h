#ifndef _FREQ_H
#define _FREQ_H

#include <stdint.h>
#include <linux/wireless.h>

typedef struct iw_freq iwfreq;

void float2freq(double in, iwfreq* out);

int freq2channel(uint16_t freq);

#endif // _FREQ_H
