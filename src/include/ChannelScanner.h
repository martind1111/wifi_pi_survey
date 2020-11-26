#ifndef _CHANNEL_SCANNER_H
#define _CHANNEL_SCANNER_H

#include <pthread.h>

#include "Worker.h"

class ApplicationContext;

void* ScanChannels(void* context);

class ChannelScanner : Worker {
public:
    ChannelScanner(ApplicationContext* context) : 
        Worker(context), channelMutex(PTHREAD_MUTEX_INITIALIZER),
        currentChannel(0), skfd(-1) { }

    void Run() override;

    int GetCurrentChannel();

private:
    int iwconfig_open();

    void iwconfig_close();

    int SetChannel(char* ifName, int channel);

    pthread_mutex_t channelMutex;

    int currentChannel;

    int skfd;
};

#endif // _CHANNEL_MONITOR_H
