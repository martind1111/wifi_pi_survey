#include "ChannelScanner.h"

#include <stdio.h>
#include <string>
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
#include <linux/if.h>
#include <linux/wireless.h>

#include <cstring>

#include "Application.h"
extern "C" {
#include "freq.h"
}
#include "HeartbeatMonitor.h"

#define LAST_CHANNEL 11

namespace {
int sockets_open(void);
}

void *
ScanChannels(void* ctx) {
    ApplicationContext* context = reinterpret_cast<ApplicationContext*>(ctx);
    ChannelScanner monitor(context);

    context->SetChannelScanner(&monitor);

    monitor.Run();

    return nullptr;
}

void
ChannelScanner::Run() {
  iwconfig_open();

  pthread_mutex_lock(&channelMutex);
  currentChannel = 1;
  pthread_mutex_unlock(&channelMutex);

  for ( ; ; ) {
    if (this->GetContext()->GetApplication()->IsShuttingDown()) {
      break;
    }

    this->GetMutableContext()->ReportActivity(ACTIVITY_SCAN_CHANNEL);

    SetChannel(this->GetContext()->dev, currentChannel);

    usleep(100000);

    pthread_mutex_lock(&channelMutex);
    currentChannel = (currentChannel % LAST_CHANNEL) + 1;
    pthread_mutex_unlock(&channelMutex);
  }

  iwconfig_close();
}

int
ChannelScanner::SetChannel(char* ifName, int channel) {
  if (skfd < 0) {
    return -1;
  }

  struct iwreq wrq;

  /* Set dev name */
  strncpy(wrq.ifr_name, ifName, IFNAMSIZ);

  double freq;

  freq = (double) channel;

  float2freq(freq, &(wrq.u.freq));

  if (ioctl(skfd, SIOCSIWFREQ, &wrq) < 0) {
    char errStr[256];

    snprintf(errStr, 256, "SIOCSIWFREQ: %s", strerror(errno));

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr);

    return -1;
  }

  return 0;
}

int
ChannelScanner::GetCurrentChannel() {
  int channel;

  pthread_mutex_lock(&channelMutex);

  channel = currentChannel;

  pthread_mutex_unlock(&channelMutex);

  return channel;
}

int
ChannelScanner::iwconfig_open() {
  skfd = -1; // Generic raw socket desc.

  // Create a channel to the NET kernel.
  if ((skfd = sockets_open()) < 0) {
    perror("socket");
    return -1;
  }

  return 0;
}

void
ChannelScanner::iwconfig_close() {
  // Close the socket.
  close(skfd);
}

namespace {
/************************ SOCKET SUBROUTINES *************************/

/*------------------------------------------------------------------*/
/*
 * Open a socket.
 * Depending on the protocol present, open the right socket. The socket
 * will allow us to talk to the driver.
 */
int
sockets_open(void) {
  int ipx_sock = -1;            /* IPX socket                   */
  int ax25_sock = -1;           /* AX.25 socket                 */
  int inet_sock = -1;           /* INET socket                  */
  int ddp_sock = -1;            /* Appletalk DDP socket         */

  inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
  ipx_sock = socket(AF_IPX, SOCK_DGRAM, 0);
  ax25_sock = socket(AF_AX25, SOCK_DGRAM, 0);
  ddp_sock = socket(AF_APPLETALK, SOCK_DGRAM, 0);

  /*
   * Now pick any (exisiting) useful socket family for generic queries
   */
  if (inet_sock!=-1)
    return inet_sock;
  if (ipx_sock!=-1)
    return ipx_sock;
  if (ax25_sock!=-1)
    return ax25_sock;
  /*
   * If this is -1 we have no known network layers and its time to jump.
   */

  return ddp_sock;
}

} // namespace
