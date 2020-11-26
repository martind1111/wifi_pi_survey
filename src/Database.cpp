#include "Database.h"

#include <stdio.h>
#include <sqlite3.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <math.h>
#include <time.h>

#include <sstream>
#include <algorithm>

#include "HeartbeatMonitor.h"
#include "Application.h"
#include "manufacturer.h"
#include "NetworkDiscovery.h"
#include "StringHelper.h"

#define WIRELESS_DB "/var/local/wireless.db"

#define SLEEP_COUNT 30

using namespace std;

namespace {
int Callback(void* data, int argc, char** argv, char** azColName);
string GetSqlite3Timestamp(const time_t timestamp);
}

void*
JournalWirelessInformation(void* ctx) {
    Database database(reinterpret_cast<ApplicationContext*>(ctx));

    database.Run();

    return nullptr;
}

void
Database::Run() {
  sqlite3* db;
  char* zErrMsg = 0;
  int rc;
  ostringstream sql;
  int sleepCount = 0;

  // Open database.
  rc = sqlite3_open(WIRELESS_DB, &db);

  if (rc) {
    fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    return;
  }

  for ( ; ; ) {
    if (this->GetContext()->GetApplication()->IsShuttingDown()) {
      break;
    }

    sleep(1);

    this->GetMutableContext()->ReportActivity(ACTIVITY_JOURNAL_DB);

    if (sleepCount < SLEEP_COUNT) {
      sleepCount++;
      continue;
    }

    sleepCount = 0;

    NetworkIterator networkIterator;
    NetworkDiscovery* networkDiscovery =
      this->GetMutableContext()->GetNetworkDiscovery();

    for (networkDiscovery->BeginNetworkIterator(networkIterator);
         !networkDiscovery->IsEndNetworkIterator(networkIterator);
         networkDiscovery->NextNetwork(networkIterator)) {
      NetworkInfo_t networkInfo;
      string bssid;

      networkDiscovery->GetNetworkIteratorBssid(networkIterator, bssid);

      if (!networkDiscovery->GetNetwork(bssid, networkInfo)) {
        continue;
      }

      // Create INSERT SQL statement.
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

      string firstSeen = GetSqlite3Timestamp(networkInfo.firstSeen);
      string lastSeen = GetSqlite3Timestamp(networkInfo.lastSeen);
      const char* manufacturer =
        getManufacturer(ether_aton(bssid.c_str()));
      string manufacturerStr;

      if (manufacturer == nullptr) {
        manufacturerStr = "";
      }
      else {
        manufacturerStr = string(manufacturer);
      }

      sql << "INSERT OR REPLACE INTO network (bssid, manufacturer, ssid, "
          << "security, channel, firstSeen, lastSeen, packetCount, latitude, "
          << "longitude, altitude) VALUES ('" << bssid
          << "', '" << manufacturerStr
          << "', '" << StringHelper::EscapeSpecialCharacters(networkInfo.ssid)
          << "', " << networkInfo.security
          << ", " << networkInfo.radiotapChannel
          << ", '" << firstSeen
          << "', '" << lastSeen
          << "', " << networkInfo.packetCount
          << ", " << latitude
          << ", " << longitude
          << ", " << altitude << ")";

      // Execute SQL statement.
      rc = sqlite3_exec(db, sql.str().c_str(), Callback, NULL,
                        &zErrMsg);

      if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL statement %s\nSQL error: %s\n", sql.str().c_str(),
                zErrMsg);
        sqlite3_free(zErrMsg);
        break;
      }

      vector<string> clients;
      networkDiscovery->GetClients(bssid, clients);
      vector<string>::const_iterator clientIter;

      for (clientIter = clients.begin(); clientIter != clients.end();
          clientIter++) {
        /* Create INSERT SQL statement */
        ClientInfo_t clientInfo;

        if (!networkDiscovery->GetClient(bssid, *clientIter, clientInfo)) {
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

        string firstSeen = GetSqlite3Timestamp(clientInfo.firstSeen);
        string lastSeen = GetSqlite3Timestamp(clientInfo.lastSeen);
        const char* manufacturer =
          getManufacturer(ether_aton(clientIter->c_str()));
        string manufacturerStr;

        if (manufacturer == nullptr) {
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

        // Execute SQL statement.
        rc = sqlite3_exec(db, sql.str().c_str(), Callback, NULL,
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
}

namespace {
int
Callback(void* data, int argc, char** argv, char** azColName) {
  return 0;
}

string
GetSqlite3Timestamp(const time_t timestamp) {
  char timeStr[32];
  struct tm brokenDownTime;

  struct tm* result = gmtime_r(&timestamp, &brokenDownTime);

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
} // namespace
