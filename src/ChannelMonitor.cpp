#include <stdio.h>
#include <cstring>
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

#include "Application.h"
//#include "wifi_types.h"

#include "HeartbeatMonitor.h"
#include "ChannelMonitor.h"

#define LAST_CHANNEL 11

typedef struct iw_freq iwfreq;

namespace {
int sockets_open(void);
void float2freq(double in, iwfreq* out);
int freq2channel(uint16_t freq);
}

void *
ScanChannels(void* ctx) {
    ApplicationContext* context = reinterpret_cast<ApplicationContext*>(ctx);
    ChannelMonitor monitor(context);

    monitor.Run();

    return nullptr;
}

void
ChannelMonitor::Run() {
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
ChannelMonitor::SetChannel(char* ifName, int channel) {
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
ChannelMonitor::GetCurrentChannel() {
  int channel;

  pthread_mutex_lock(&channelMutex);

  channel = currentChannel;

  pthread_mutex_unlock(&channelMutex);

  return channel;
}

int
ChannelMonitor::iwconfig_open() {
  skfd = -1; // Generic raw socket desc.

  // Create a channel to the NET kernel.
  if ((skfd = sockets_open()) < 0) {
    perror("socket");
    return -1;
  }

  return 0;
}

void
ChannelMonitor::iwconfig_close() {
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

/********************** FREQUENCY SUBROUTINES ***********************/

/*------------------------------------------------------------------*/
/*
 * Convert a floating point to our internal representation of
 * frequencies.
 * The kernel doesn't want to hear about floating point, so we use
 * this custom format instead.
 */
void
float2freq(double in, iwfreq* out) {
  out->e = (short) (floor(log10(in)));
  if (out->e > 8) {
    out->m = ((long) (floor(in / pow(10, out->e - 6)))) * 100;
    out->e -= 8;
  }
  else {
    out->m = in;
    out->e = 0;
  }
}

int
freq2channel(uint16_t freq) {
  if (freq >= 2412 && freq <= 2472) {
    return ((freq - 2412) / 5) + 1;
  }

  if (freq == 2484) {
    return 14;
  }

  if (freq >= 5180 && freq <= 5320) {
    return 4 * ((freq - 5180) / 20) + 36;
  }

  if (freq >= 5745 && freq <= 5809) {
    return 4 * ((freq - 5745) / 20) + 149;
  }

  return 0;
}
} // namespace
