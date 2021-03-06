#include "HardwareHelper.h"

#include <stdio.h>
#include <pcre.h>
#include <string.h>
#include <netinet/ether.h>

#include <string>
#include <map>
#include <fmt/core.h>
#include <iostream>
#include <sstream>

#define OVECCOUNT 30

using namespace std;

static bool loaded = false;
static map<string, string> manufacturers;

namespace {
void LoadManufacturers();
}

const char* MANUFACTURER_PATH = "/usr/share/wireshark/manuf";

namespace {
void
LoadManufacturers() {
  FILE* f;
  size_t len = 0;
  char* line;
  const char* error;
  int erroroffset;
  int ovector[OVECCOUNT];
  pcre* re;
  int rc;
  string oui;
  string manufacturer;

  loaded = true;

  f = fopen(MANUFACTURER_PATH, "r");

  if (f == NULL) {
    fprintf(stderr, "File %s not present\n", MANUFACTURER_PATH);

    return;
  }

  re = pcre_compile("^([\\dA-F]{2,}:[\\dA-F]{2,}:[\\dA-F]{2,})\\s+(\\S+)\\s",
                    0,
                    &error,
                    &erroroffset,
                    NULL);

  if (re == NULL) {
    fprintf(stderr, "Failed parsing manufacturer file\n");

    return;
  }

  for ( ; ; ) {
    ssize_t sz = getline(&line, &len, f);

    if (sz == -1) {
      break;
    }

    if (line[0] == '#') {
      // Skip comment.
      continue;
    }

    rc = pcre_exec(re,
                   NULL,
                   line,
                   static_cast<int>(strlen(line)),
                   0,
                   0,
                   ovector,
                   OVECCOUNT);

    if (rc < 0) {
      if (rc == PCRE_ERROR_NOMATCH) {
        continue;
      }
    }
    else if (rc >= 3) {
      oui = string(line, ovector[2], ovector[3] - ovector[2]);

      manufacturer = string(line, ovector[4], ovector[5] - ovector[4]);
    }

    manufacturers.insert(make_pair(oui, manufacturer));
  }

  free(line);
}
} // namespace

const char *
HardwareHelper::GetManufacturer(struct ether_addr* addr) {
  map<string, string>::const_iterator iter;

  if (!loaded) {
    LoadManufacturers();
  }

  string oui = fmt::format("{:02X}:{:02X}:{:02X}", addr->ether_addr_octet[0],
                           addr->ether_addr_octet[1],
                           addr->ether_addr_octet[2]);

  iter = manufacturers.find(oui);

  if (iter != manufacturers.end()) {
    return iter->second.c_str();
  }

  return nullptr;
}

