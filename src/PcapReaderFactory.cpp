#include "PcapReaderFactory.h"

#include "PcapReader.h"
#include "PcapFileReader.h"
#include "InterfaceReader.h"
#include "Application.h"

using namespace std;

PcapReader*
PcapReaderFactory::MakePcapReader(ApplicationContext* context) {
    if (context->dev) {
        return new InterfaceReader(context);
    }

    if (context->fileName) {
        return new PcapFileReader(context);
    }

    return nullptr;
}
