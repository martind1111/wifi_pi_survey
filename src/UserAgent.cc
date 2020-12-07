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

#include "UserAgent.h"

#include <stdio.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <math.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <syslog.h>
#include <netinet/ether.h>
#include <wiringPiI2C.h>

#include <string>
#include <sstream>
#include <fmt/core.h>
#include <fmt/chrono.h>

#include "airodump-ng.h"
#include "pkt.h"
extern "C" {
#include "create_pid_file.h"
}
#include "NetworkDiscovery.h"
#include "Database.h"
#include "HardwareHelper.h"
#include "Application.h"
#include "HeartbeatMonitor.h"
#include "OutputHelper.h"
#include "I2cController.h"
#include "ConsoleDisplay.h"
#include "LcdDisplay.h"
#include "DisplayFactory.h"
#include "I2cController.h"

using namespace std;

namespace {
int WaitForKeyboardInput(unsigned int seconds);
const string GetLocationString(const double latitude,
                               const double longitude);
const char* GetCommandString(Command command);
}

void*
UserAgentRunner(void* context) {
    UserAgent userAgent(reinterpret_cast<ApplicationContext*>(context));

    userAgent.Run();

    return nullptr;
}

void
UserAgent::ExecuteCurrentCommand(Command& currentCommand) {
  switch(currentCommand) {
  case COMMAND_NEXT:
    if (menuState == MENU_NETWORKS) {
      ChooseNextNetwork();
    }
    else if (menuState == MENU_NETWORK_DETAILS) {
      if (networkDetailState == DETAIL_NET_CLIENTS) {
        if (!ChooseNextClient()) {
          ChooseNextNetworkDetail();
        }
      }
      else {
        ChooseNextNetworkDetail();
      }
    }
    else {
      ChooseNextClientDetail();
    }
    break;
  case COMMAND_ZOOM_IN:
    if (menuState == MENU_NETWORKS) {
      menuState = MENU_NETWORK_DETAILS;
      networkDetailState = DETAIL_NET_MANUFACTURER;
      currentClient = "";
    }
    else if (menuState == MENU_NETWORK_DETAILS) {
      if (networkDetailState == DETAIL_NET_CLIENTS) {
        menuState = MENU_CLIENT_DETAILS;
        clientDetailState = DETAIL_CLIENT_MANUFACTURER;
      }
    }
    currentCommand = COMMAND_NEXT;
    break;
  case COMMAND_ZOOM_OUT:
    if (menuState == MENU_NETWORK_DETAILS) {
      menuState = MENU_NETWORKS;
    }
    else {
      menuState = MENU_NETWORK_DETAILS;
    }
    currentCommand = COMMAND_NEXT;
    break;
  case COMMAND_FILTER_PROTECTED:
    filter = true;
    ApplyFilter();
    currentCommand = COMMAND_NO_FILTER;
    break;
  case COMMAND_NO_FILTER:
    filter = false;
    currentCommand = COMMAND_FILTER_PROTECTED;
    break;
  case COMMAND_RESET:
    if (menuState == MENU_GPS) {
      this->GetMutableContext()->ResetLocation();
      currentCommand = COMMAND_WIFI;
    }
    else {
      ResetNetworks();
      currentCommand = COMMAND_NEXT;
    }
    break;
  case COMMAND_GPS:
    menuState = MENU_GPS;
    currentCommand = COMMAND_WIFI;
    break;
  case COMMAND_WIFI:
    menuState = MENU_NETWORKS;
    currentCommand = COMMAND_NEXT;
    break;
  }
}

void
UserAgent::Run() {
  char line[MAX_LINE_LENGTH + 2];
  bool lastLedOpenState;
  bool lastLedWepState;
  bool lastLedWpaState;
  ostringstream lastZone1, lastZone2, lastZone3, lastZone4, lastZone5,
    lastZone6;
  ostringstream zone1, zone2, zone3, zone4, zone5, zone6;

  menuState = MENU_NETWORKS;
  Command currentCommand = COMMAND_NEXT;
  filter = false;
  lastLedOpenState = false;
  lastLedWepState = false;
  lastLedWpaState = false;

  NetworkIterator& networkIterator =
    this->GetMutableContext()->networkIterator;
  NetworkDiscovery* networkDiscovery =
    this->GetMutableContext()->GetNetworkDiscovery();

  networkDiscovery->BeginNetworkIterator(networkIterator);

  i2cController.Init();

  if (!i2cController.IsOperational()) {
    string errStr = "I2C failure: Disabling interactions with IgORE board";

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr.c_str());

    if (this->GetContext()->interactive) {
      fprintf(stderr, "%s\n", errStr.c_str());
    }
  }

  SetLed(REG_STATUS_LED, lastLedOpenState);
  SetLed(REG_EXT2_LED, lastLedWepState);
  SetLed(REG_EXT1_LED, lastLedWpaState);

  lastZone1.str("");
  lastZone2.str("");
  lastZone3.str("");
  lastZone4.str("");
  lastZone5.str("");

  InitDisplay(&i2cController);

  ClearScreen();

  for ( ; ; ) {
    if (this->GetContext()->GetApplication()->IsShuttingDown()) {
      break;
    }

    this->GetMutableContext()->ReportActivity(ACTIVITY_DISPLAY_MENU);

    if (IsLcdReset()) {
      lastZone1.str("");
      lastZone2.str("");
      lastZone3.str("");
      lastZone4.str("");
      lastZone5.str("");
      Reset();
      ClearScreen();
    }

    string currentNetworkSnapshot;
    uint32_t networkCountSnapshot;
    string currentClientSnapshot;

    networkCountSnapshot = networkDiscovery->GetNetworkCount();

    networkDiscovery->GetNetworkIteratorBssid(networkIterator,
                                              currentNetworkSnapshot);
    currentClientSnapshot = currentClient;

    bool ledOpenState = networkDiscovery->IsOpenNetwork();
 
    if (ledOpenState != lastLedOpenState) {
      SetLed(REG_STATUS_LED, ledOpenState);
    }

    lastLedOpenState = ledOpenState;

    bool ledWepState = networkDiscovery->IsWepNetwork();
 
    if (ledWepState != lastLedWepState) {
      SetLed(REG_EXT2_LED, ledWepState);
    }

    lastLedWepState = ledWepState;

    bool ledWpaState = networkDiscovery->IsWpaNetwork();
 
    if (ledWpaState != lastLedWpaState) {
      SetLed(REG_EXT1_LED, ledWpaState);
    }

    lastLedWpaState = ledWpaState;

    zone1.str("");
    zone2.str("");
    zone3.str("");
    zone4.str("");
    zone5.str("");
    zone6.str("");

    zone6 << GetCommandString(currentCommand);

    NetworkInfo_t networkInfo;
    bool networkFound = networkDiscovery->GetNetwork(currentNetworkSnapshot,
                                                     networkInfo);

    if ((menuState == MENU_NETWORKS || menuState == MENU_NETWORK_DETAILS) &&
        !networkFound) {
        zone3 << networkCountSnapshot;
    }
    else if (menuState == MENU_NETWORKS || menuState == MENU_NETWORK_DETAILS) {
      if (networkInfo.ssid.size() > 16) {
        zone1 << networkInfo.ssid.substr(0, 13) << "...";
      }
      else {
        zone1 << networkInfo.ssid;
      }

      zone2 << OutputHelper::GetSecurityString(networkInfo.security);
      if (networkCountSnapshot < 100) {
          zone3 << networkCountSnapshot;
      }
      else {
          zone3 << "*" << (networkCountSnapshot % 10);
      }

      if (menuState == MENU_NETWORKS) {
        zone4 << currentNetworkSnapshot;
        const char* signalStr = 
          networkDiscovery->GetBestClientSignal(currentNetworkSnapshot);
        if (signalStr != NULL) {
          zone5 << signalStr;
        }
      }
      else if (menuState == MENU_NETWORK_DETAILS) {
        string timeStr;
        string channelStr;
        string packetStr;
        string locationStr;
        switch(networkDetailState) {
        case DETAIL_NET_MANUFACTURER:
          {
            struct ether_addr* addr =
              ether_aton(currentNetworkSnapshot.c_str());
            zone4 << HardwareHelper::GetManufacturer(addr);
          }
          break;
        case DETAIL_NET_FIRST_SEEN:
          {
            timeStr = fmt::format("F: {:%Y-%m-%d %H:%M:%S}",
                                  fmt::localtime(networkInfo.firstSeen));
            zone4 << timeStr.substr(0, MAX_LINE_LENGTH);
          }
          break;
        case DETAIL_NET_LAST_SEEN:
          {
            timeStr = fmt::format("L: {:%Y-%m-%d %H:%M:%S}",
                                  fmt::localtime(networkInfo.lastSeen));
            zone4 << timeStr.substr(0, MAX_LINE_LENGTH);
          }
          break;
        case DETAIL_NET_CHANNEL:
          channelStr = fmt::format("Channel: {:<3d}", networkInfo.channel);
          zone4 << channelStr.substr(0, MAX_LINE_LENGTH);
          break;
        case DETAIL_NET_PACKET_COUNT:
          packetStr =
            fmt::format("Packets: {:<10d}", networkInfo.packetCount);
          zone4 << packetStr.substr(0, MAX_LINE_LENGTH);
          break;
        case DETAIL_NET_LOCATION:
          locationStr = GetLocationString(networkInfo.location.latitude,
                                          networkInfo.location.longitude);
          zone4 << locationStr.substr(0, MAX_LINE_LENGTH);
          break;
        case DETAIL_NET_CLIENTS:
          if (currentClientSnapshot.empty()) {
            ChooseNextClient();
            currentClientSnapshot = currentClient;
          }

          zone4 << currentClientSnapshot;
          break;
        }
      }
    }

    if (menuState == MENU_CLIENT_DETAILS) {
      zone1 << currentClientSnapshot.c_str();

      ClientInfo_t client;
      bool clientFound = networkDiscovery->GetClient(currentNetworkSnapshot,
                                                     currentClientSnapshot,
                                                     client);

      string timeStr;
      string packetStr;
      switch(clientDetailState) {
      case DETAIL_CLIENT_MANUFACTURER:
        {
          struct ether_addr *addr =
            ether_aton(currentClientSnapshot.c_str());
          zone4 << HardwareHelper::GetManufacturer(addr);
        }
        break;
      case DETAIL_CLIENT_FIRST_SEEN:
        {
          timeStr = fmt::format("F: {:%Y-%m-%d %H:%M:%s}",
                                fmt::localtime(client.firstSeen));
          zone4 << timeStr.substr(0, MAX_LINE_LENGTH);
        }
        break;
      case DETAIL_CLIENT_LAST_SEEN:
        {
          timeStr = fmt::format("L: {:%Y-%m-%d %H:%M:%S}",
                                fmt::localtime(client.lastSeen));
          zone4 << timeStr.substr(0, MAX_LINE_LENGTH);
        }
        break;
      case DETAIL_CLIENT_PACKET_COUNT:
        packetStr = fmt::format("Packets: {:<10d}", client.packetCount);
        zone4 << packetStr.substr(0, MAX_LINE_LENGTH);
        break;
      case DETAIL_CLIENT_SIGNAL_NOISE:
        if (client.dbmSignal != 0) {
          zone4 << "Signal: " << ((int32_t) client.dbmSignal) << " ";
        }
        if (client.dbmNoise != 0) {
          zone4 << "Noise: " <<  ((int32_t) client.dbmNoise);
        }
        break;
      default:
        break;
      }
    }

    if (menuState == MENU_GPS) {
      double latitude, longitude;

      latitude = this->GetContext()->lastLocation.latitude;
      longitude = this->GetContext()->lastLocation.longitude;

      const string& locationStr = GetLocationString(latitude, longitude);
      zone1 << locationStr.substr(0, MAX_LINE_LENGTH);

      string distanceStr =
        fmt::format("Distance: {:.3f}", this->GetContext()->totalDistance);
      zone4 << distanceStr.substr(0, MAX_LINE_LENGTH);
    }

    if (zone2.str() != lastZone2.str()) {
      MoveCursor(0, 17);
      sprintf(line, "%-5s", zone2.str().c_str());
      PrintLine(line);
    }

    if (zone3.str() != lastZone3.str()) {
      MoveCursor(0, 22);
      sprintf(line, "%2s", zone3.str().c_str());
      PrintLine(line);
    }

    if (zone1.str() != lastZone1.str()) {
      MoveCursor(0, 0);
      if (zone2.str().empty()) {
        sprintf(line, "%-24s", zone1.str().c_str());
      }
      else {
        sprintf(line, "%-17s", zone1.str().c_str());
      }
      PrintLine(line);
    }

    if (zone5.str() != lastZone5.str()) {
      MoveCursor(1, 18);
      sprintf(line, "%-3s", zone5.str().c_str());
      PrintLine(line);
    }

    if (zone4.str() != lastZone4.str()) {
      MoveCursor(1, 0);
      if (zone5.str().empty()) {
        sprintf(line, "%-23s", zone4.str().c_str());
      }
      else {
        sprintf(line, "%-18s", zone4.str().c_str());
      }

      PrintLine(line);
    }

    if (zone6.str() != lastZone6.str()) {
      MoveCursor(1, 23);
      PrintLine(zone6.str().c_str());
    }

#if DEBUG
    if (zone1.str() != lastZone1.str() ||
        zone2.str() != lastZone2.str() ||
        zone3.str() != lastZone3.str() ||
        zone4.str() != lastZone4.str() ||
        zone5.str() != lastZone5.str() ||
        zone6.str() != lastZone6.str()) {
      if (zone2.str().empty()) {
        fprintf(stdout, "%-21s %2s\n", zone1.str().c_str(),
                zone3.str().c_str());
      }
      else {
        fprintf(stdout, "%-16s %-4s %2s\n", zone1.str().c_str(),
                zone2.str().c_str(), zone3.str().c_str());
      }

      if (zone5.str().empty()) {
        fprintf(stdout, "%-23s%1s\n", zone4.str().c_str(), zone6.str().c_str());
      }
      else {
        fprintf(stdout, "%-18s %-3s %1s\n", zone4.str().c_str(),
                zone5.str().c_str(), zone6.str().c_str());
      }
    }
#endif

    lastZone1.str(zone1.str());
    lastZone2.str(zone2.str());
    lastZone3.str(zone3.str());
    lastZone4.str(zone4.str());
    lastZone5.str(zone5.str());
    lastZone6.str(zone6.str());

    EchoOff();

    char c;

    int status = GetButton();

    if (status == BUTTON_STATUS_SHORT) {
      c = '.';
    }
    else if (status == BUTTON_STATUS_LONG) {
      c = ' ';
    }

    if (status != BUTTON_STATUS_SHORT && status != BUTTON_STATUS_LONG) {
      if (this->GetContext()->interactive) {
        int status = WaitForKeyboardInput(1);

        if (status != 1) {
          continue;
        }

        c = getc(stdin);
      }
      else {
        continue;
      }
    }

    if (c == 'x') {
      pcap_breakloop(this->GetContext()->descr);

      this->GetMutableContext()->GetApplication()->Shutdown();

      continue;
    }

    if (c == ' ') {
      // Long button pressed: Select next command.
      ChooseNextCommand(currentCommand);

      continue;
    }

    // Short button pressed: Execute current command.
    ExecuteCurrentCommand(currentCommand);
  }

  EchoOn();
}

LcdDisplay*
UserAgent::GetLcdDisplay() {
  if (!i2cController.IsOperational()) {
    return nullptr;
  }

  DisplayPtr displayPtr = displays.front();

  if (!displayPtr) {
      return nullptr;
  }

  return reinterpret_cast<LcdDisplay*>(displayPtr.get());
}

int
UserAgent::GetButton() {
  if (!i2cController.IsOperational()) {
    return 0;
  }

  int reg_value = wiringPiI2CReadReg8(i2cController.GetFileDescr(), REG_BUTTON);

  if (reg_value == -1) {
    string errStr =
      fmt::format("Error reading register 0x{:02X} from I2C slave device "
                  "0x{:02X}", REG_BUTTON, DEVICE_ADDRESS);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr.c_str());

    return 0;
  }

  int status =
    wiringPiI2CWriteReg8(i2cController.GetFileDescr(), REG_BUTTON, 0);

  if (status == -1) {
    string errStr =
      fmt::format("Error writing register 0x{:02X} on I2C slave device "
                  "0x{:02X)", REG_BUTTON, DEVICE_ADDRESS);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr.c_str());

    return 0;
  }

  return reg_value;
}

void
UserAgent::SetLed(int reg, bool state) {
  if (!i2cController.IsOperational()) {
    return;
  }

  int status = wiringPiI2CWriteReg8(i2cController.GetFileDescr(), reg, state);

  if (status == -1) {
    string errStr = 
      fmt::format("Failed writing to register 0x{:02X} on I2C slave device "
                  "0x{:02X}", REG_STATUS_LED, DEVICE_ADDRESS);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr.c_str());
  }
}

void
UserAgent::InitDisplay(const I2cController* i2cController) {
  if (i2cController->IsOperational()) {
    LcdDisplay* display =
      DisplayFactory::MakeLcdDisplay(i2cController->GetFileDescr());
    DisplayPtr displayPtr = shared_ptr<Display>(display);

    if (this->GetContext()->debugLcdDisplay) {
      display->Debug();
    }

    displays.push_back(displayPtr);
  }

  if (this->GetContext()->interactive) {
    DisplayPtr displayPtr =
      shared_ptr<Display>(DisplayFactory::MakeConsoleDisplay());

    displays.push_back(displayPtr);
  }

  for (auto& displayPtr : displays) {
    displayPtr->Init();
  }
}

void
UserAgent::ClearScreen() {
  for (auto& display : displays) {
    display->ClearScreen();
  }
}

void
UserAgent::PrintLine(const char* line) {
  for (auto& display : displays) {
    display->Print(line, false);
  }
}

void
UserAgent::Print(const char* line, bool line_feed) {
  for (auto& display : displays) {
    display->Print(line, line_feed);
  }
}

bool
UserAgent::IsLcdReset() {
  LcdDisplay* display = GetLcdDisplay();

  if (!display) {
    return false;
  }

  return display->IsReset();
}

void
UserAgent::Reset() {
  for (auto& display : displays) {
    display->Reset();
  }
}

void
UserAgent::MoveCursor(int row, int column) {
  for (auto& display : displays) {
    display->MoveCursor(row, column);
  }
}

void
UserAgent::EchoOn() {
  for (auto& display : displays) {
    display->EchoOn();
  }
}

void
UserAgent::EchoOff() {
  for (auto& display : displays) {
    display->EchoOff();
  }
}

void
UserAgent::ChooseNextCommand(Command& currentCommand) {
  switch(currentCommand) {
  case COMMAND_NEXT:
    if (menuState == MENU_NETWORKS ||
        (menuState == MENU_NETWORK_DETAILS &&
         networkDetailState == DETAIL_NET_CLIENTS)) {
      currentCommand = COMMAND_ZOOM_IN;
    }
    else {
      currentCommand = COMMAND_ZOOM_OUT;
    }
    break;
  case COMMAND_ZOOM_IN:
    if (menuState != MENU_NETWORKS) {
      currentCommand = COMMAND_ZOOM_OUT;
      break;
    }

    if (filter) {
      currentCommand = COMMAND_NO_FILTER;
    }
    else {
      currentCommand = COMMAND_FILTER_PROTECTED;
    }
    break;
  case COMMAND_ZOOM_OUT:
    if (filter) {
      currentCommand = COMMAND_NO_FILTER;
    }
    else {
      currentCommand = COMMAND_FILTER_PROTECTED;
    }
    break;
  case COMMAND_FILTER_PROTECTED:
    currentCommand = COMMAND_RESET;
    break;
  case COMMAND_NO_FILTER:
    currentCommand = COMMAND_RESET;
    break;
  case COMMAND_RESET:
    if (menuState == MENU_GPS) {
      currentCommand = COMMAND_WIFI;
    }
    else {
      currentCommand = COMMAND_GPS;
    }
    break;
  case COMMAND_GPS:
    currentCommand = COMMAND_NEXT;
    break;
  case COMMAND_WIFI:
    currentCommand = COMMAND_RESET;
    break;
  default:
    break;
  }
}

void
UserAgent::ChooseNextNetwork() {
  NetworkIterator& networkIterator =
    this->GetMutableContext()->networkIterator;
  NetworkDiscovery* networkDiscovery =
    this->GetMutableContext()->GetNetworkDiscovery();

  if (networkDiscovery->IsEndNetworkIterator(networkIterator)) {
    return;
  }

  networkDiscovery->NextNetwork(networkIterator);

  ApplyFilter();
}

/**
 * Ensure the current AP is compiant to the filter setting. If filter is true,
 * which means we are filtering out protected networks, ensure that current AP
 * is open. If it isn't find the next one that is.
 */
void
UserAgent::ApplyFilter() {
  string currentBssid;
  NetworkDiscovery* networkDiscovery =
    this->GetMutableContext()->GetNetworkDiscovery();
  NetworkIterator& networkIterator =
    this->GetMutableContext()->networkIterator;

  networkDiscovery->GetNetworkIteratorBssid(networkIterator, currentBssid);

  for ( ; !networkDiscovery->IsEndNetworkIterator(networkIterator);
       networkDiscovery->NextNetwork(networkIterator)) {
    if (!filter) {
      break;
    }
    else {
      string bssid;

      if (networkDiscovery->GetNetworkIteratorBssid(networkIterator, bssid)) {
        NetworkInfo_t networkInfo;

        if (networkDiscovery->GetNetwork(bssid, networkInfo)) {
          if (networkInfo.security & STD_OPN) {
            break;
          }
        }
      }
    }
  }

  if (!networkDiscovery->IsEndNetworkIterator(networkIterator)) {
    return;
  }

  for (networkDiscovery->BeginNetworkIterator(networkIterator);
       !networkDiscovery->IsEndNetworkIterator(networkIterator);
       networkDiscovery->NextNetwork(networkIterator)) {
    string bssid;

    if (!networkDiscovery->GetNetworkIteratorBssid(networkIterator, bssid)) {
      networkDiscovery->EndNetworkIterator(networkIterator);
      break;
    }

    if (bssid.compare(currentBssid) == 0) {
      networkDiscovery->EndNetworkIterator(networkIterator);
      break;
    }

    if (!filter) {
      break;
    }
    else {
      NetworkInfo_t networkInfo;

      if (networkDiscovery->GetNetwork(bssid, networkInfo)) {
        if (networkInfo.security & STD_OPN) {
          break;
        }
      }
    }
  }
}

bool
UserAgent::ChooseNextClient() {
  string bssid;
  int i;
  NetworkIterator& networkIterator =
    this->GetMutableContext()->networkIterator;
  NetworkDiscovery* networkDiscovery =
    this->GetMutableContext()->GetNetworkDiscovery();

  if (!networkDiscovery->GetNetworkIteratorBssid(networkIterator, bssid)) {
    return false;
  }

  vector<string> clients;

  networkDiscovery->GetClients(bssid, clients);

  if (currentClient.empty()) {
    // If there is no client defined, return the first client in the list
    // of clients associated with the current AP.
    if (!clients.empty()) {
      currentClient = clients.at(0);
      return true;
    }
  }


  for (i = 0; i < clients.size(); i++) {
    string client = clients.at(i);

    if (client.compare(currentClient) != 0) {
      continue;
    }

    if (i != clients.size() - 1) {
      currentClient = clients.at(i + 1);

      return true;
    }
  }

  return false;
}

void
UserAgent::ChooseNextClientDetail() {
  clientDetailState++;
}

void
UserAgent::ChooseNextNetworkDetail() {
  networkDetailState++;

  if (networkDetailState == DETAIL_NET_CLIENTS) {
    currentClient = "";
  }
}

void
UserAgent::ResetNetworks() {
  NetworkIterator& networkIterator =
    this->GetMutableContext()->networkIterator;
  NetworkDiscovery* networkDiscovery =
    this->GetMutableContext()->GetNetworkDiscovery();

  networkDiscovery->ReleaseNetworkResources();

  networkDiscovery->BeginNetworkIterator(networkIterator);

  currentClient = "";
}

namespace {
int
WaitForKeyboardInput(unsigned int seconds) {
  /* File descriptor set on which to wait */
  fd_set set;
  /* Time structure which indicate the amount of time to
     wait. 0 will perform a poll */
  struct timeval timeout;

  /* Initialize the file descriptor set. */
  FD_ZERO(&set);
  /* Use the standard input as the descriptor on which to wait */
  FD_SET(STDIN_FILENO, &set);

  /* Initialize the timeout data structure. */
  timeout.tv_sec = seconds;
  timeout.tv_usec = 0;

  /* select returns 0 if timeout, 1 if input available, -1 if error. */
  /* and is only waiting on the input selection */
  return TEMP_FAILURE_RETRY(select(FD_SETSIZE,
                            &set, NULL, NULL,
                            &timeout));
}

const string
GetLocationString(const double latitude, const double longitude) {
  ostringstream str;
  if (!isnan(latitude)) {
    str << fmt::format("{:2.6f} ", latitude);
  }
  else {
    str << "-- ";
  }
  if (!isnan(longitude)) {
    str << fmt::format("{:2.6f}", longitude);
  }
  else {
    str << "--";
  }

  return str.str();
}

const char*
GetCommandString(Command command) {
  switch(command) {
  case COMMAND_NEXT:
    return "+";
  case COMMAND_BACK:
    return "-";
  case COMMAND_ZOOM_IN:
    return ">";
  case COMMAND_ZOOM_OUT:
    return "<";
  case COMMAND_FILTER_PROTECTED:
    return "F";
  case COMMAND_NO_FILTER:
    return "N";
  case COMMAND_RESET:
    return "X";
  case COMMAND_GPS:
    return "G";
  case COMMAND_WIFI:
    return "W";
  }

  return "?";
}

} // namespace
