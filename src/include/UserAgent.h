#ifndef _USER_AGENT_H
#define _USER_AGENT_H

#include <string>
#include <vector>
#include <memory>

#include "Worker.h"
#include "NetworkDiscovery.h"
#include "I2cController.h"
#include "DisplayManager.h"

enum MenuState {
  MENU_NETWORKS,
  MENU_NETWORK_DETAILS,
  MENU_CLIENT_DETAILS,
  MENU_GPS
};

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

enum NetworkDetailState {
  DETAIL_NET_MANUFACTURER,
  DETAIL_NET_FIRST_SEEN,
  DETAIL_NET_LAST_SEEN,
  DETAIL_NET_CHANNEL,
  DETAIL_NET_PACKET_COUNT,
  DETAIL_NET_LOCATION,
  DETAIL_NET_CLIENTS,
  DETAIL_NET_LAST
};

inline NetworkDetailState
operator++(NetworkDetailState& ns, int) {
  const NetworkDetailState prev = ns;
  const int last = static_cast<int>(DETAIL_NET_LAST);
  const int i = static_cast<int>(ns);
  ns = static_cast<NetworkDetailState>((i + 1) % last);
  return prev;
}

enum ClientDetailState {
  DETAIL_CLIENT_MANUFACTURER,
  DETAIL_CLIENT_FIRST_SEEN,
  DETAIL_CLIENT_LAST_SEEN,
  DETAIL_CLIENT_PACKET_COUNT,
  DETAIL_CLIENT_SIGNAL_NOISE,
  DETAIL_CLIENT_LAST
};

inline ClientDetailState
operator++(ClientDetailState& cs, int) {
  const ClientDetailState prev = cs;
  const int last = static_cast<int>(DETAIL_CLIENT_LAST);
  const int i = static_cast<int>(cs);
  cs = static_cast<ClientDetailState>((i + 1) % last);
  return prev;
}

void* UserAgentRunner(void* context);

class ApplicationContext;
class NetworkDiscovery;

class UserAgent : Worker {
public:
    UserAgent(ApplicationContext* context) : Worker(context) { }

    void Run() override;

private:
    int GetButton();
    void SetLed(int reg, bool state);

    void ExecuteNetworkMenu(NetworkDiscovery* networkDiscovery,
                            const NetworkInfo& networkInfo,
                            uint32_t networkCountSnapshot,
                            const std::string& currentNetworkSnapshot,
                            std::string& currentClientSnapshot,
                            std::vector<std::string>& zones);
    void ExecuteClientMenu(NetworkDiscovery* networkDiscovery,
                           const std::string& currentClientSnapshot,
                           const std::string& currentNetworkSnapshot,
                           std::vector<std::string>& zones);
    void ExecuteGpsMenu(std::vector<std::string>& zones);
    void ExecuteCurrentCommand(Command& currentCommand);
    void RenderDisplay(const std::vector<std::string>& zones,
                       const std::vector<std::string>& lastZones);
    bool HandleInput(Command& currentCommand);
    void ChooseNextCommand(Command& currentCommand);
    void ChooseNextNetwork();
    bool ChooseNextClient();
    void ChooseNextNetworkDetail();
    void ChooseNextClientDetail();
    void ResetNetworks();
    void ApplyFilter();

    MenuState menuState;

    std::string currentClient;

    NetworkDetailState networkDetailState;

    ClientDetailState clientDetailState;

    bool filter;

    std::unique_ptr<I2cController> i2c_controller;

    std::unique_ptr<DisplayManager> display_manager;
};

#endif // _USER_AGENT_H
