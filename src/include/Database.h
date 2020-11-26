#ifndef _DATABASE_H
#define _DATABASE_H

#include "Worker.h"

void* JournalWirelessInformation(void* ctx);

class Database : Worker {
public:
    Database(ApplicationContext* context) : Worker(context) { }

    void Run() override;
};
#endif // _DATABASE_H
