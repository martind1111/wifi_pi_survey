/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * This executable retrieves all network and client equipments from the
 * sqlite3 database and generates a KML file that can be imported into
 * Google Earth to display network and client equipments on a geo map.
 */

#include <stdio.h>
#include <sqlite3.h>
#include <math.h>
#include <string.h>
#include <sstream>
#include <stdlib.h>

#include "StringHelper.h"
#include "airodump-ng.h"

#define WIRELESS_DB "/var/local/wireless.db"
#define FILENAME_KML "network.kml"

using namespace std;

namespace {
int Callback(void* data, int argc, char** argv, char** azColName);
void PrintStyles(FILE *f);

int
Callback(void* data, int argc, char** argv, char** azColName){
  int i;
  char bssid[32];
  char ssid[64];
  char manufacturer[32];
  char latitude[16];
  char longitude[16];
  char altitude[16];
  char security[16];
  int securityMask;

  strcpy(manufacturer, "");

  FILE *f = (FILE *) data;

  for (i= 0; i < argc; i++) {
    if (strcmp(azColName[i], "ssid") == 0) {
      sprintf(ssid, "%s", argv[i] ? argv[i] : "NULL");
    }
    if (strcmp(azColName[i], "bssid") == 0) {
      sprintf(bssid, "%s", argv[i] ? argv[i] : "NULL");
    }
    if (strcmp(azColName[i], "manufacturer") == 0) {
      sprintf(manufacturer, "%s", argv[i] ? argv[i] : "");
    }
    if (strcmp(azColName[i], "latitude") == 0) {
      sprintf(latitude, "%s", argv[i] ? argv[i] : "NULL");
    }
    if (strcmp(azColName[i], "longitude") == 0) {
      sprintf(longitude, "%s", argv[i] ? argv[i] : "NULL");
    }
    if (strcmp(azColName[i], "altitude") == 0) {
      sprintf(altitude, "%s", argv[i] ? argv[i] : "NULL");
    }
    if (strcmp(azColName[i], "security") == 0) {
      securityMask = argv[i] ? atoi(argv[i]) : 0;
      if (securityMask & STD_OPN) {
        sprintf(security, "OPEN");
      }
      else if (securityMask & STD_WEP) {
        sprintf(security, "WEP");
      }
      else if (securityMask & STD_WPA2) {
        sprintf(security, "WPA2");
      }
      else if (securityMask & STD_WPA) {
        sprintf(security, "WPA");
      }
      else {
        sprintf(security, "UNKNOWN");
      }
    }
  }

  if (strcmp(latitude, "0.0") == 0 && strcmp(longitude, "0.0") == 0) {
    // Skip network that does not have coordinates.
    return 0;
  }

  fprintf(f, "  <Placemark>\n");
  if (ssid != NULL && strlen(ssid) != 0) {
    string escaped = StringHelper::EscapeHtml(string(ssid));
    fprintf(f, "    <name>%s</name>\n", escaped.c_str());
  }
  else if (bssid != NULL && strlen(bssid) != 0) {
    fprintf(f, "    <name>%s</name>\n", bssid);
  }

  if (manufacturer[0] != '\0') {
    string escaped = StringHelper::EscapeHtml(string(manufacturer));
    fprintf(f, "    <description>%s</description>\n", escaped.c_str());
  }

  if (strcmp(security, "OPEN") == 0) {
    fprintf(f, "    <styleUrl>#openIcon</styleUrl>\n");
  }
  else if (strcmp(security, "WEP") == 0) {
    fprintf(f, "    <styleUrl>#wepIcon</styleUrl>\n");
  }
  else if (strcmp(security, "WPA") == 0 || strcmp(security, "WPA2") == 0) {
    fprintf(f, "    <styleUrl>#wpaIcon</styleUrl>\n");
  }
  else {
    fprintf(f, "    <styleUrl>#unknownIcon</styleUrl>\n");
  }

  fprintf(f, "    <Point>\n"
          "      <coordinates>%s,%s</coordinates>\n"
          "    </Point>\n", longitude, latitude);
  fprintf(f, "  </Placemark>\n");

  return 0;
}

void
PrintStyles(FILE *f) {
  fprintf(f, "  <Style id=\"openIcon\">\n");
  fprintf(f, "    <IconStyle>\n");
  fprintf(f, "      <Icon>\n");
  fprintf(f, "        <href>http://maps.google.com/mapfiles/kml/pushpin/grn-pushpin.png</href>\n");
  fprintf(f, "      </Icon>\n");
  fprintf(f, "    </IconStyle>\n");
  fprintf(f, "  </Style>\n");
  fprintf(f, "  <Style id=\"wepIcon\">\n");
  fprintf(f, "    <IconStyle>\n");
  fprintf(f, "      <Icon>\n");
  fprintf(f, "        <href>http://maps.google.com/mapfiles/kml/pushpin/ylw-pushpin.png</href>\n");
  fprintf(f, "      </Icon>\n");
  fprintf(f, "    </IconStyle>\n");
  fprintf(f, "  </Style>\n");
  fprintf(f, "  <Style id=\"wpaIcon\">\n");
  fprintf(f, "    <IconStyle>\n");
  fprintf(f, "      <Icon>\n");
  fprintf(f, "        <href>http://maps.google.com/mapfiles/kml/pushpin/red-pushpin.png</href>\n");
  fprintf(f, "      </Icon>\n");
  fprintf(f, "    </IconStyle>\n");
  fprintf(f, "  </Style>\n");
  fprintf(f, "  <Style id=\"unknownIcon\">\n");
  fprintf(f, "    <IconStyle>\n");
  fprintf(f, "      <Icon>\n");
  fprintf(f, "        <href>http://maps.google.com/mapfiles/kml/pushpin/blue-pushpin.png</href>\n");
  fprintf(f, "      </Icon>\n");
  fprintf(f, "    </IconStyle>\n");
  fprintf(f, "  </Style>\n");
}
} // namespace

int
main(int argc, char* argv[]) {
  sqlite3* db;
  char errstr[256];
  char *zErrMsg = 0;
  int rc;
  ostringstream sql;
  const char *data;
  FILE* f = NULL;

  f = fopen(FILENAME_KML, "w");

  if (f == NULL) {
    sprintf(errstr, "Failed exporting network information to KML: "
            "Can't open file %s", FILENAME_KML);
    perror(errstr);
    return 0;
  }

  fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
          "<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n"
          "<Document>\n");

  PrintStyles(f);

  /* Open database */
  rc = sqlite3_open(WIRELESS_DB, &db);

  if (rc) {
     fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));

     return 0;
  }

  sql << "SELECT ssid, bssid, manufacturer, security, latitude, longitude "
         "FROM network";

  /* Execute SQL statement */
  rc = sqlite3_exec(db, sql.str().c_str(), Callback, (void *) f,
                    &zErrMsg);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  }

  sqlite3_close(db);

  fprintf(f, "</Document>\n"
          "</kml>\n");

  fclose(f);

  return 0;
}
