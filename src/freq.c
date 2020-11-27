#include "freq.h"

/********************** FREQUENCY SUBROUTINES ***********************/

/*------------------------------------------------------------------*/
/*
 * Convert a floating point to our internal representation of
 * frequencies.
 * The kernel doesn't want to hear about floating point, so we use
 * this custom format instead.
 */
void
float2freq(double in, iwfreq* out) {
  out->e = (short) (floor(log10(in)));
  if (out->e > 8) {
    out->m = ((long) (floor(in / pow(10, out->e - 6)))) * 100;
    out->e -= 8;
  }
  else {
    out->m = in;
    out->e = 0;
  }
}

int
freq2channel(uint16_t freq) {
  if (freq >= 2412 && freq <= 2472) {
    return ((freq - 2412) / 5) + 1;
  }

  if (freq == 2484) {
    return 14;
  }

  if (freq >= 5180 && freq <= 5320) {
    return 4 * ((freq - 5180) / 20) + 36;
  }

  if (freq >= 5745 && freq <= 5809) {
    return 4 * ((freq - 5745) / 20) + 149;
  }

  return 0;
}

