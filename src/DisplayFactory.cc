#include "DisplayFactory.h"

#include "LcdDisplay.h"
#include "ConsoleDisplay.h"

LcdDisplay*
DisplayFactory::MakeLcdDisplay(int fd) {
    return new LcdDisplay(fd);
}

ConsoleDisplay*
DisplayFactory::MakeConsoleDisplay() {
    return new ConsoleDisplay();
}
