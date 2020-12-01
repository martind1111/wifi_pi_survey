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

#include "Database.h"

#include <stdio.h>
#include <sqlite3.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <math.h>
#include <time.h>

#include <sstream>
#include <algorithm>

#include <fmt/core.h>
#include <fmt/chrono.h>

#include "HeartbeatMonitor.h"
#include "Application.h"
#include "HardwareHelper.h"
#include "NetworkDiscovery.h"
#include "StringHelper.h"

#define WIRELESS_DB "/var/local/wireless.db"

#define SLEEP_COUNT 30

using namespace std;

namespace {
void Init();
int Callback(void* data, int argc, char** argv, char** azColName);
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

  Init();

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

      string firstSeen = fmt::format("{:%Y-%m-%d %H:%M:%S}",
                                     fmt::localtime(networkInfo.firstSeen));
      string lastSeen = fmt::format("{:%Y-%m-%d %H:%M:%S}",
                                    fmt::localtime(networkInfo.lastSeen));
      const char* manufacturer =
        HardwareHelper::GetManufacturer(ether_aton(bssid.c_str()));
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

        string firstSeen = fmt::format("{:%Y-%m-%d %H:%M:%S}",
                                       fmt::localtime(clientInfo.firstSeen));
        string lastSeen = fmt::format("{:%Y-%m-%d %H:%M:%S}",
                                      fmt::localtime(clientInfo.lastSeen));
        const char* manufacturer =
          HardwareHelper::GetManufacturer(ether_aton(clientIter->c_str()));
        string manufacturerStr;

        if (manufacturer == nullptr) {
          manufacturerStr = "";
        }
        else {
          manufacturerStr = string(manufacturer);
        }

        sql << "INSERT OR REPLACE INTO client (macAddress, manufacturer, "
               "bssid, ssid, rate, dbmSignal, dbmNoise, firstSeen, lastSeen, "
               "packetCount, latitude, longitude, altitude) VALUES ('" 
            << *clientIter << "', '" << manufacturerStr << "', '" << bssid
            << "', '" << networkInfo.ssid
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
void Init() {
  sqlite3* db;
  char* zErrMsg = 0;
  int rc;
  ostringstream sql;

  // Open database.
  rc = sqlite3_open(WIRELESS_DB, &db);

  if (rc) {
    fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    return;
  }

  sql << "CREATE TABLE IF NOT EXISTS network ("
      << "bssid TEXT, "
      << "manufacturer TEXT, "
      << "ssid TEXT KEY, "
      << "security INTEGER DEFAULT 0, "
      << "channel INTEGER DEFAULT 0, "
      << "firstSeen TEXT, "
      << "lastSeen TEXT, "
      << "packetCount INTEGER DEFAULT 0, "
      << "latitude REAL DEFAULT 0, "
      << "longitude REAL DEFAULT 0, "
      << "altitude REAL DEFAULT 0, "
      << "PRIMARY KEY (bssid, ssid))";

  // Execute SQL statement.
  rc = sqlite3_exec(db, sql.str().c_str(), Callback, NULL,
                    &zErrMsg);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL statement %s\nSQL error: %s\n",
            sql.str().c_str(), zErrMsg);
    sqlite3_free(zErrMsg);
  }

  sql.str("");
  sql << "CREATE TABLE IF NOT EXISTS client ("
      << "macAddress TEXT, "
      << "manufacturer TEXT, "
      << "bssid TEXT, "
      << "ssid TEXT, "
      << "rate INTEGER DEFAULT 0, "
      << "dbmSignal INTEGER DEFAULT 0, "
      << "dbmNoise INTEGER DEFAULT 0, "
      << "firstSeen TEXT, "
      << "lastSeen TEXT, "
      << "packetCount INTEGER DEFAULT 0, "
      << "latitude REAL DEFAULT 0, "
      << "longitude REAL DEFAULT 0, "
      << "altitude REAL DEFAULT 0, "
      << "PRIMARY KEY (macAddress))";

  // Execute SQL statement.
  rc = sqlite3_exec(db, sql.str().c_str(), Callback, NULL,
                    &zErrMsg);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL statement %s\nSQL error: %s\n",
            sql.str().c_str(), zErrMsg);
    sqlite3_free(zErrMsg);
  }

  sqlite3_close(db);
}

int
Callback(void* data, int argc, char** argv, char** azColName) {
  return 0;
}
} // namespace
