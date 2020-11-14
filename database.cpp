#include <stdio.h>
#include <sqlite3.h>
#include <unistd.h>
#include <sstream>
#include <map>
#include <algorithm>
#include <netinet/ether.h>
#include <math.h>
#include <time.h>

#include "heartbeat.h"
#include "manufacturer.h"
#include "string_utils.h"
#include "networkDiscovery.h"

#define WIRELESS_DB "/var/local/wireless.db"

#define SLEEP_COUNT 30

using namespace std;

static int callback(void *data, int argc, char **argv, char **azColName);
static string getSqlite3Timestamp(const time_t timestamp);

static int
callback(void *data, int argc, char **argv, char **azColName) {
  return 0;
}

void *
journalWirelessInformation(void *ctx) {
  sqlite3 *db;
  char *zErrMsg = 0;
  int rc;
  ostringstream sql;
  int sleepCount = 0;

  /* Open database */
  rc = sqlite3_open(WIRELESS_DB, &db);

  if (rc) {
    fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    return NULL;
  }

  for ( ; ; ) {
    if (isSurveyDone()) {
      break;
    }

    sleep(1);

    reportActivity(ACTIVITY_JOURNAL_DB);

    if (sleepCount < SLEEP_COUNT) {
      sleepCount++;
      continue;
    }

    sleepCount = 0;

    NetworkIterator_t networkIterator;

    for (beginNetworkIterator(networkIterator);
         !isEndNetworkIterator(networkIterator); nextNetwork(networkIterator)) {
      NetworkInfo_t networkInfo;
      string bssid;

      getNetworkIteratorBssid(networkIterator, bssid);

      if (!getNetwork(bssid, networkInfo)) {
        continue;
      }

      /* Create INSERT SQL statement */
      sql.str("");

      double latitude = 0.0;
      double longitude = 0.0;
      double altitude = 0.0;

      if (!isnan(networkInfo.location.latitude)) {
        latitude = networkInfo.location.latitude;
      }

      if (!isnan(networkInfo.location.longitude)) {
        longitude = networkInfo.location.longitude;
      }

      if (!isnan(networkInfo.location.altitude)) {
        altitude = networkInfo.location.altitude;
      }

      string firstSeen = getSqlite3Timestamp(networkInfo.firstSeen);
      string lastSeen = getSqlite3Timestamp(networkInfo.lastSeen);
      const char *manufacturer =
        getManufacturer(ether_aton(bssid.c_str()));
      string manufacturerStr;

      if (manufacturer == NULL) {
        manufacturerStr = "";
      }
      else {
        manufacturerStr = string(manufacturer);
      }

      sql << "INSERT OR REPLACE INTO network (bssid, manufacturer, ssid, "
          << "security, channel, firstSeen, lastSeen, packetCount, latitude, "
          << "longitude, altitude) VALUES ('" << bssid
          << "', '" << manufacturerStr
          << "', '" << escapeSpecialCharacters(networkInfo.ssid)
          << "', " << networkInfo.security
          << ", " << networkInfo.radiotapChannel
          << ", '" << firstSeen
          << "', '" << lastSeen
          << "', " << networkInfo.packetCount
          << ", " << latitude
          << ", " << longitude
          << ", " << altitude << ")";

      /* Execute SQL statement */
      rc = sqlite3_exec(db, sql.str().c_str(), callback, NULL,
                        &zErrMsg);

      if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL statement %s\nSQL error: %s\n", sql.str().c_str(),
                zErrMsg);
        sqlite3_free(zErrMsg);
        break;
      }

      vector<string> clients;
      getClients(bssid, clients);
      vector<string>::const_iterator clientIter;

      for (clientIter = clients.begin(); clientIter != clients.end();
          clientIter++) {
        /* Create INSERT SQL statement */
        ClientInfo_t clientInfo;

        if (!getClient(bssid, *clientIter, clientInfo)) {
          continue;
        }

        sql.str("");

        double latitude = 0.0;
        double longitude = 0.0;
        double altitude = 0.0;

        if (!isnan(clientInfo.location.latitude)) {
          latitude = clientInfo.location.latitude;
        }

        if (!isnan(clientInfo.location.longitude)) {
          longitude = clientInfo.location.longitude;
        }

        if (!isnan(clientInfo.location.altitude)) {
          altitude = clientInfo.location.altitude;
        }

        string firstSeen = getSqlite3Timestamp(clientInfo.firstSeen);
        string lastSeen = getSqlite3Timestamp(clientInfo.lastSeen);
        const char *manufacturer =
          getManufacturer(ether_aton(clientIter->c_str()));
        string manufacturerStr;

        if (manufacturer == NULL) {
          manufacturerStr = "";
        }
        else {
          manufacturerStr = string(manufacturer);
        }

        sql << "INSERT OR REPLACE INTO client (bssid, manufacturer, "
            << "rate, dbmSignal, dbmNoise, firstSeen, lastSeen, packetCount, "
            << "latitude, longitude, altitude) VALUES ('" << bssid
            << "', '" << manufacturerStr
            << "', " << clientInfo.rate
            << ", " << ((int32_t) clientInfo.dbmSignal)
            << ", " << ((int32_t) clientInfo.dbmNoise)
            << ", '" << firstSeen
            << "', '" << lastSeen
            << "', " << clientInfo.packetCount
            << ", " << latitude
            << ", " << longitude
            << ", " << altitude << ")";

        /* Execute SQL statement */
        rc = sqlite3_exec(db, sql.str().c_str(), callback, NULL,
                          &zErrMsg);

        if (rc != SQLITE_OK) {
          fprintf(stderr, "'%s' SQL statement %s\nSQL error: %s\n",
                  manufacturerStr.c_str(),
                  sql.str().c_str(), zErrMsg);
          sqlite3_free(zErrMsg);
          break;
        }
      }
    }
  }

  sqlite3_close(db);

  return NULL;
}

static string
getSqlite3Timestamp(const time_t timestamp) {
  char timeStr[32];
  struct tm brokenDownTime;

  struct tm *result = gmtime_r(&timestamp, &brokenDownTime);

  if (result == NULL) {
    sprintf(timeStr, "%lu", timestamp);

    return string(timeStr);
  }

  sprintf(timeStr, "%04d-%02d-%02d %02d:%02d:%02d",
         1900 + brokenDownTime.tm_year,
          brokenDownTime.tm_mon + 1, brokenDownTime.tm_mday, 
          brokenDownTime.tm_hour, brokenDownTime.tm_min,
          brokenDownTime.tm_sec);

  return string(timeStr);
}
