#ifndef _INTERFACE_READER_H
#define _INTERFACE_READER_H

#include "Worker.h"

class ApplicationContext;

void* MonitorInterface(void* context);

class InterfaceReader : Worker {
public:
    InterfaceReader(ApplicationContext* context) : Worker(context) { }

    void Run() override;
};

#endif // _INTERFACE_READER_H
