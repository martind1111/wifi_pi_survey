#ifndef _DISPLAY_OUTPUT_H
#define _DISPLAY_OUTPUT_H

#include <string>

#include "Worker.h"

class ApplicationContext;

typedef enum {
  MENU_NETWORKS,
  MENU_NETWORK_DETAILS,
  MENU_CLIENT_DETAILS,
  MENU_GPS
} MenuState_t;

typedef enum {
  COMMAND_NEXT,
  COMMAND_BACK,
  COMMAND_ZOOM_IN,
  COMMAND_ZOOM_OUT,
  COMMAND_FILTER_PROTECTED,
  COMMAND_NO_FILTER,
  COMMAND_FILTER,
  COMMAND_RESET,
  COMMAND_GPS,
  COMMAND_WIFI
} Command_t;

typedef enum {
  DETAIL_NET_MANUFACTURER,
  DETAIL_NET_FIRST_SEEN,
  DETAIL_NET_LAST_SEEN,
  DETAIL_NET_CHANNEL,
  DETAIL_NET_PACKET_COUNT,
  DETAIL_NET_LOCATION,
  DETAIL_NET_CLIENTS,
  DETAIL_NET_LAST
} NetworkDetailState_t;

inline NetworkDetailState_t
operator++(NetworkDetailState_t& ns, int) {
  const NetworkDetailState_t prev = ns;
  const int last = static_cast<int>(DETAIL_NET_LAST);
  const int i = static_cast<int>(ns);
  ns = static_cast<NetworkDetailState_t>((i + 1) % last);
  return prev;
}

typedef enum {
  DETAIL_CLIENT_MANUFACTURER,
  DETAIL_CLIENT_FIRST_SEEN,
  DETAIL_CLIENT_LAST_SEEN,
  DETAIL_CLIENT_PACKET_COUNT,
  DETAIL_CLIENT_SIGNAL_NOISE,
  DETAIL_CLIENT_LAST
} ClientDetailState_t;

inline ClientDetailState_t
operator++(ClientDetailState_t& cs, int) {
  const ClientDetailState_t prev = cs;
  const int last = static_cast<int>(DETAIL_CLIENT_LAST);
  const int i = static_cast<int>(cs);
  cs = static_cast<ClientDetailState_t>((i + 1) % last);
  return prev;
}

void* DisplayMenu(void* context);

class DisplayOutput : Worker {
public:
    DisplayOutput(ApplicationContext* context) : Worker(context) { }

    void Run() override;

private:
    bool IsI2cOperational();
    int GetButton();
    void SetLed(int reg, bool state);
    void ClearScreen();
    void PrintLine(const char* line);
    void OutputLcd(const char* line, bool lineFeed);
    bool IsLcdReset();
    void ClearLcdReset();
    void LcdMoveCursor(int row, int column);

    void ChooseNextCommand();
    void ChooseNextNetwork();
    bool ChooseNextClient();
    void EchoOn();
    void EchoOff();
    void ChooseNextNetworkDetail();
    void ChooseNextClientDetail();
    void ResetNetworks();
    void ApplyFilter();

    bool i2c_oper;
    int i2c_fd;

    MenuState_t menuState;

    Command_t currentCommand;

    std::string currentClient;

    NetworkDetailState_t networkDetailState;

    ClientDetailState_t clientDetailState;

    bool filter;
};

#endif // _DISPLAY_OUTPUT_H
