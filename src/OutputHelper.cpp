#include "OutputHelper.h"

#include "airodump-ng.h"

const char*
OutputHelper::GetSecurityString(uint32_t security) {
  if (security & STD_OPN) {
    return "OPEN";
  }
  else if (security & STD_WEP) {
    return "WEP ";
  }
  else if (security & STD_WPA) {
    return "WPA ";
  }
  else if (security & STD_WPA2) {
    return "WPA2";
  }

  return "UNKN";
}

