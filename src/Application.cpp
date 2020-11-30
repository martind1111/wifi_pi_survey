#include "Application.h"

#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <getopt.h>
#include <syslog.h>

#include <cstring>

extern "C" {
#include "create_pid_file.h"
}
#include "NetworkDiscovery.h"
#include "Database.h"
#include "PcapReader.h"
#include "GpsMonitor.h"
#include "ChannelScanner.h"
#include "HeartbeatMonitor.h"
#include "DisplayOutput.h"

#define DEFAULT_ACTIVITY_THRESHOLD 30

using namespace std;

static pthread_mutex_t shutdownMutex = PTHREAD_MUTEX_INITIALIZER;

static bool done = false;

namespace {
char *copy_argv(char** argv);
void ParseArguments(int argc, char* argv[], ApplicationContext* context);
}

void
ApplicationContext::ReportActivity(const Activity_t activity) {
  if (heartbeatMonitor) {
    // Delegate to HeartbeatMonitor instance.
    heartbeatMonitor->ReportActivity(activity);
  }
}

void
ApplicationContext::ResetLocation() {
  if (gpsMonitor) {
    // Delegate to GpsMonitor instance.
    gpsMonitor->ResetLocation();
  }
}

int
ApplicationContext::GetCurrentChannel() {
  if (channelScanner) {
    // Delegate to ChannelScanner instance.
    return channelScanner->GetCurrentChannel();
  }

  return 0;
}

bool
Application::IsShuttingDown() const {
  bool d;

  pthread_mutex_lock(&shutdownMutex);
  d = done;
  pthread_mutex_unlock(&shutdownMutex);

  return d;
}

void
Application::Shutdown() {
  pthread_mutex_lock(&shutdownMutex);

  done = true;

  pthread_mutex_unlock(&shutdownMutex);
}

void
Application::LogError(int opmode, const char* module,
                      const char* message) const {
  fprintf(stderr, "%s: %s\n", module, message);
}

namespace {
/*
 * copy_argv - Copy the rest of an argument string into a new buffer for
 *             processing.
 */
char*
copy_argv(char** argv) {
  char** p;
  size_t len = 0;
  char* buf;
  char* src;
  char* dst;

  p = argv;

  if (*p == 0)
    return 0;

  while (*p)
    len += strlen(*p++) + 1;

  buf = reinterpret_cast<char*>(malloc(len));
  if (buf == NULL) {
    fprintf(stderr, "copy_argv: malloc");
    exit(1);
  }

  p = argv;
  dst = buf;
  while ((src = *p++) != NULL) {
    while ((*dst++ = *src++) != '\0')
      ;
    dst[-1] = ' ';
  }
  dst[-1] = '\0';

  return buf;
}

void
ParseArguments(int argc, char* argv[], ApplicationContext* context) {
  context->dev = NULL;
  context->fileName = NULL;
  context->eflag = 0;
  context->interactive = false;
  context->npkts = -1;
  context->oper = NULL;
  context->vflag = 3;
  context->out = NULL;
  context->outPcap = NULL;
  context->dumper = NULL;
  context->priority = LOG_USER | LOG_LOCAL3 | LOG_INFO;
  context->activityThreshold = DEFAULT_ACTIVITY_THRESHOLD;

  context->debugLcdDisplay = false;
  context->debugGps = false;

  while (1) {
    static struct option long_options[] = {
      {"ethernet",           no_argument,       0, 'e'},
      {"interface",          required_argument, 0, 'i'},
      {"interactive",        no_argument,       0, 'I'},
      {"output",             required_argument, 0, 'o'},
      {"output-pcap",        required_argument, 0, 'w'},
      {"polls",              required_argument, 0, 'p'},
      {"input-pcap",         required_argument, 0, 'r'},
      {"verbose",            required_argument, 0, 'v'},
      {"debug-lcd",          no_argument,       0, 'l'},
      {"debug-gps",          no_argument,       0, 'g'},
      {"activity-threshold", required_argument, 0, 't'},
      {0,0,0,0}
    };

    int option_index = 0;

    int c = getopt_long(argc, argv, "ei:Ip:v:o:r:w:lg", long_options,
                        &option_index);

    if (c == -1)
      break;

    switch (c) {
      case 'e':
        context->eflag = 1;
        break;
      case 'i':
        context->dev = optarg;
        break;
      case 'I':
        context->interactive = true;
        break;
      case 'o':
        context->out = fopen(optarg, "w");
        break;
      case 'p':
        context->npkts = atoi(optarg);
        break;
      case 'r':
        context->fileName = optarg;
        break;
      case 'w':
        context->outPcap = fopen(optarg, "w");
        break;
      case 'l':
        context->debugLcdDisplay = true;
        break;
      case 'g':
        context->debugGps = true;
        break;
      case 't':
        context->activityThreshold = atoi(optarg);
        break;
      default:
        break;
    }
  }

  if (context->out == NULL) {
    context->out = fopen("/dev/null", "w");
  }

  argc -= optind;
  argv += optind;

  context->oper = copy_argv(argv);
}
} // namespace

int
main(int argc, char** argv) {
  Application application;
  ApplicationContext context(&application);
  NetworkDiscovery networkDiscovery(&context);
  pthread_t gpsThreadId;
  pthread_t interfaceThreadId;
  pthread_t displayThreadId;
  pthread_t scanChannelsThreadId;
  pthread_t journalWirelessInfoThreadId;
  pthread_t heartbeatThreadId;

  createPidFile("wscand", "/var/run/wscand.pid", CPF_CLOEXEC);

  ParseArguments(argc, argv, &context);

  context.SetNetworkDiscovery(&networkDiscovery);

  if (getuid()) {
    fprintf(stderr, "Error! Must be root... Exiting\n");
    return(1);
  }

  pthread_create(&gpsThreadId, NULL, MonitorGps, &context);

  pthread_create(&interfaceThreadId, NULL, MonitorPcap, &context);

  pthread_create(&displayThreadId, NULL, DisplayMenu, &context);

  pthread_create(&scanChannelsThreadId, NULL, ScanChannels, &context);

  pthread_create(&journalWirelessInfoThreadId, NULL, JournalWirelessInformation,
                 &context);

  pthread_create(&heartbeatThreadId, NULL, MonitorHeartbeat, &context);

  pthread_join(gpsThreadId, NULL);

  pthread_join(interfaceThreadId, NULL);

  pthread_join(displayThreadId, NULL);

  pthread_join(scanChannelsThreadId, NULL);

  pthread_join(journalWirelessInfoThreadId, NULL);

  pthread_join(heartbeatThreadId, NULL);

  fprintf(stdout, "Shutting down...\n");

  networkDiscovery.DisplayNetworks();

  networkDiscovery.ReleaseNetworkResources();

  return 0;
}
