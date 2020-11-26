#include "DisplayOutput.h"

#include <stdio.h>
#include <math.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <math.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <termios.h>
#include <syslog.h>
#include <netinet/ether.h>

#include <string>
#include <sstream>

#include <fmt/core.h>
#include <fmt/chrono.h>
#include "wiringPiI2C.h"

#include "airodump-ng.h"
#include "pkt.h"
#include "wifi_types.h"
extern "C" {
#include "create_pid_file.h"
}
#include "NetworkDiscovery.h"
#include "Database.h"
#include "manufacturer.h"
#include "Application.h"
#include "HeartbeatMonitor.h"
#include "OutputHelper.h"

#define MAX_LINE_LENGTH 24

#define DEVICE_ADDRESS 0x50

#define LCD_SIZE 64

#define REG_LCD 0x00
#define REG_LCD_RESET 0x3F

#define LCD_CLEAR_SCREEN 0x0C
#define LCD_MOVE_CURSOR 0x1B

#define REG_STATUS_LED 0x41
#define REG_EXT1_LED 0x43
#define REG_EXT2_LED 0x44

#define REG_BUTTON 0x42
#define BUTTON_STATUS_SHORT 1
#define BUTTON_STATUS_LONG 2

using namespace std;

namespace {
int WaitForKeyboardInput(unsigned int seconds);
const string GetLocationString(const double latitude,
                               const double longitude);
const char* GetCommandString(Command_t command);
}

void*
DisplayMenu(void* context) {
    DisplayOutput output(reinterpret_cast<ApplicationContext*>(context));

    output.Run();

    return nullptr;
}

void
DisplayOutput::Run() {
  char line[MAX_LINE_LENGTH + 2];
  bool lastLedOpenState;
  bool lastLedWepState;
  bool lastLedWpaState;
  ostringstream lastZone1, lastZone2, lastZone3, lastZone4, lastZone5,
    lastZone6;
  ostringstream zone1, zone2, zone3, zone4, zone5, zone6;

  i2c_fd = wiringPiI2CSetup(DEVICE_ADDRESS);

  menuState = MENU_NETWORKS;
  currentCommand = COMMAND_NEXT;
  filter = false;
  lastLedOpenState = false;
  lastLedWepState = false;
  lastLedWpaState = false;

  NetworkIterator& networkIterator =
    this->GetMutableContext()->networkIterator;
  NetworkDiscovery* networkDiscovery =
    this->GetMutableContext()->GetNetworkDiscovery();

  networkDiscovery->BeginNetworkIterator(networkIterator);

  i2c_oper = IsI2cOperational();

  if (!i2c_oper) {
    string errStr =
      fmt::format("I2C failure: Disabling interactions with IgORE board");

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr.c_str());

    if (this->GetContext()->interactive) {
      fprintf(stderr, "%s\n", errStr);
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
      ClearLcdReset();
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
            zone4 << getManufacturer(addr);
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
            fmt::format("Packets: {<10d}", networkInfo.packetCount);
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
          zone4 << getManufacturer(addr);
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

    if (zone2.str().compare(lastZone2.str()) != 0) {
      LcdMoveCursor(0, 17);
      sprintf(line, "%-5s", zone2.str().c_str());
      PrintLine(line);
    }

    if (zone3.str().compare(lastZone3.str()) != 0) {
      LcdMoveCursor(0, 22);
      sprintf(line, "%2s", zone3.str().c_str());
      PrintLine(line);
    }

    if (zone1.str().compare(lastZone1.str()) != 0) {
      LcdMoveCursor(0, 0);
      if (zone2.str().empty()) {
        sprintf(line, "%-24s", zone1.str().c_str());
      }
      else {
        sprintf(line, "%-17s", zone1.str().c_str());
      }
      PrintLine(line);
    }

    if (zone5.str().compare(lastZone5.str()) != 0) {
      LcdMoveCursor(1, 18);
      sprintf(line, "%-3s", zone5.str().c_str());
      PrintLine(line);
    }

    if (zone4.str().compare(lastZone4.str()) != 0) {
      LcdMoveCursor(1, 0);
      if (zone5.str().empty()) {
        sprintf(line, "%-23s", zone4.str().c_str());
      }
      else {
        sprintf(line, "%-18s", zone4.str().c_str());
      }

      PrintLine(line);
    }

    if (zone6.str().compare(lastZone6.str()) != 0) {
      LcdMoveCursor(1, 23);
      PrintLine(zone6.str().c_str());
    }

    if (this->GetContext()->interactive &&
        (zone1.str().compare(lastZone1.str()) != 0 ||
         zone2.str().compare(lastZone2.str()) != 0 ||
         zone3.str().compare(lastZone3.str()) != 0 ||
         zone4.str().compare(lastZone4.str()) != 0 ||
         zone5.str().compare(lastZone5.str()) != 0 ||
         zone6.str().compare(lastZone6.str()) != 0)) {
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
      if  (this->GetContext()->interactive) {
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
      ChooseNextCommand();

      continue;
    }

    // Short button pressed: Execute current command.
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

  EchoOn();
}

bool
DisplayOutput::IsI2cOperational() {
  int status = wiringPiI2CReadReg8(i2c_fd, REG_BUTTON);

  return status != -1;
}

int
DisplayOutput::GetButton() {
  char errStr[80];

  if (!i2c_oper) {
    return 0;
  }

  int regValue = wiringPiI2CReadReg8(i2c_fd, REG_BUTTON);

  if (regValue == -1) {
    string errStr =
      fmt::format("Error reading register 0x{:02X} from I2C slave device "
                  "0x{:02X}", REG_BUTTON, DEVICE_ADDRESS);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr.c_str());

    return 0;
  }

  int status = wiringPiI2CWriteReg8(i2c_fd, REG_BUTTON, 0);

  if (status == -1) {
    string errStr =
      fmt::format("Error writing register 0x{:02X} on I2C slave device "
                  "0x{:02X)", REG_BUTTON, DEVICE_ADDRESS);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr.c_str());

    return 0;
  }

  return regValue;
}

void
DisplayOutput::SetLed(int reg, bool state) {
  if (!i2c_oper) {
    return;
  }

  int status = wiringPiI2CWriteReg8(i2c_fd, reg, state);

  if (status == -1) {
    string errStr = 
      fmt::format("Failed writing to register 0x{:02X} on I2C slave device "
                  "0x{:02X}", REG_STATUS_LED, DEVICE_ADDRESS);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr.c_str());
  }
}

void
DisplayOutput::ClearScreen() {
  char str[2];

  str[0] = LCD_CLEAR_SCREEN;
  str[1] = '\0';

  OutputLcd(str, false);
}

void
DisplayOutput::PrintLine(const char* line) {
  OutputLcd(line, false);
}

bool
DisplayOutput::IsLcdReset() {
  if (!i2c_oper) {
    return false;
  }

  int regValue = wiringPiI2CReadReg8(i2c_fd, REG_LCD_RESET);

  if (regValue == -1) {
    string errStr =
      fmt::format("Error reading register 0x{:02X} from I2C slave device "
                  "0x{:02X}", REG_LCD_RESET, DEVICE_ADDRESS);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr.c_str());

    return false;
  }

  if (regValue != 0) {
    if (this->GetContext()->debugLcdDisplay) {
      string debugStr = fmt::format("LCD Display: Detected reset");

      syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr.c_str());
    }

    return true;
  }

  return false;
}

void
DisplayOutput::ClearLcdReset() {
  if (!i2c_oper) {
    return;
  }

  int status = wiringPiI2CWriteReg8(i2c_fd, REG_LCD_RESET, 0x00);

  if (status == -1) {
    string errStr =
      fmt::format("Error writing register 0x{:02X} on I2C slave device "
                  "0x{:02X}", REG_LCD_RESET, DEVICE_ADDRESS);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr.c_str());

    return;
  }

  if (this->GetContext()->debugLcdDisplay) {
    string debugStr = fmt::format("LCD Display: Clear");

    syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr.c_str());
  }
}

void
DisplayOutput::LcdMoveCursor(int row, int column) {
  if (!i2c_oper) {
    return;
  }

  if (this->GetContext()->debugLcdDisplay) {
    string debugStr =
      fmt::format("LCD Display: Move cursor to row {}, column {}", row,
                  column);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr.c_str());
  }

  string cmd =
    fmt::format("sudo i2cset -y 1 0{:02x} 0x{:02x} 0x{:02x} 0x{:02x} 0x00 i",
                DEVICE_ADDRESS, REG_LCD + 1, row, column);

  system(cmd.c_str());

  cmd = fmt::format("sudo i2cset -y 1 0x{:02x} 0x{:02x} 0x{:02x} i",
                    DEVICE_ADDRESS, REG_LCD, LCD_MOVE_CURSOR);

  system(cmd.c_str());
}

void
DisplayOutput::OutputLcd(const char* line, bool lineFeed) {
  if (!i2c_oper) {
    return;
  }

  if (this->GetContext()->debugLcdDisplay) {
    string debugStr = fmt::format("LCD Display: Output '{}'", line);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr.substr(0, 80).c_str());
  }

  ostringstream cmd;
  string str;
  int len = strlen(line);
  int i;

  if (len > LCD_SIZE - 1) {
    len = LCD_SIZE - 1;
  }

  cmd << fmt::format("sudo i2cset -y 1 0x{:02x} 0x{:02x} ", DEVICE_ADDRESS,
                     REG_LCD);

  for (i = 0; i < len; i++) {
    str = fmt::format("0x{:02x} ", line[i]);
    cmd << str;
  }

  if (lineFeed) {
    cmd << "0x0a ";
  }

  cmd << "0x00 i";

  system(cmd.str().c_str());
}

void
DisplayOutput::ChooseNextCommand() {
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
DisplayOutput::ChooseNextNetwork() {
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
DisplayOutput::ApplyFilter() {
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
DisplayOutput::ChooseNextClient() {
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
DisplayOutput::ChooseNextClientDetail() {
  clientDetailState++;
}

void
DisplayOutput::EchoOff() {
  // Define a terminal configuration data structure
  struct termios term;

  // Copy the stdin terminal configuration into term
  tcgetattr(fileno(stdin), &term);

  // Turn off Canonical processing in term
  term.c_lflag &= ~ICANON;

  // Turn off screen echo in term
  term.c_lflag &= ~ECHO;

  // Set the terminal configuration for stdin according to term, now
  tcsetattr( fileno(stdin), TCSANOW, &term);
}

void
DisplayOutput::EchoOn() {
  // Define a terminal configuration data structure
  struct termios term;

  // Copy the stdin terminal configuration into term
  tcgetattr(fileno(stdin), &term);

  // Turn on Canonical processing in term
  term.c_lflag |= ICANON;

  // Turn on screen echo in term
  term.c_lflag |= ECHO;

  // Set the terminal configuration for stdin according to term, now
  tcsetattr( fileno(stdin), TCSANOW, &term);
}

void
DisplayOutput::ChooseNextNetworkDetail() {
  networkDetailState++;

  if (networkDetailState == DETAIL_NET_CLIENTS) {
    currentClient = "";
  }
}

void
DisplayOutput::ResetNetworks() {
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
GetCommandString(Command_t command) {
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
