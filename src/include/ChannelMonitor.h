#ifndef _CHANNEL_MONITOR_H
#define _CHANNEL_MONITOR_H

#include "Worker.h"

class ApplicationContext;

void* ScanChannels(void* context);

class ChannelMonitor : Worker {
public:
   ChannelMonitor(ApplicationContext* context) : 
       Worker(context), channelMutex(PTHREAD_MUTEX_INITIALIZER),
       currentChannel(0), skfd(-1) { }

   void Run() override;

private:
    int iwconfig_open();

    void iwconfig_close();

    int SetChannel(char* ifName, int channel);

    int GetCurrentChannel();

    pthread_mutex_t channelMutex;

    int currentChannel;

    int skfd;
};

#endif // _CHANNEL_MONITOR_H
