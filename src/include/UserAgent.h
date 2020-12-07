#ifndef _USER_AGENT_H
#define _USER_AGENT_H

#include <string>
#include <list>
#include <memory>

#include "Worker.h"
#include "I2cController.h"

typedef enum {
  MENU_NETWORKS,
  MENU_NETWORK_DETAILS,
  MENU_CLIENT_DETAILS,
  MENU_GPS
} MenuState_t;

enum Command {
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
};

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

void* UserAgentRunner(void* context);

class ApplicationContext;
class Display;
class LcdDisplay;

using DisplayPtr = std::shared_ptr<Display>;

class UserAgent : Worker {
public:
    UserAgent(ApplicationContext* context) : Worker(context) { }

    void Run() override;

private:
    int GetButton();
    void SetLed(int reg, bool state);
    void InitDisplay(const I2cController* i2cController);
    void ClearScreen();
    void PrintLine(const char* line);
    void Print(const char* line, bool line_feed);
    bool IsLcdReset();
    void Reset();
    void MoveCursor(int row, int column);
    void EchoOn();
    void EchoOff();
    LcdDisplay* GetLcdDisplay();

    void ExecuteCurrentCommand(Command& currentCommand);
    void ChooseNextCommand(Command& currentCommand);
    void ChooseNextNetwork();
    bool ChooseNextClient();
    void ChooseNextNetworkDetail();
    void ChooseNextClientDetail();
    void ResetNetworks();
    void ApplyFilter();

    MenuState_t menuState;

    std::string currentClient;

    NetworkDetailState_t networkDetailState;

    ClientDetailState_t clientDetailState;

    bool filter;

    I2cController i2cController;

    std::list<DisplayPtr> displays;
};

#endif // _USER_AGENT_H
