#ifndef _DISPLAY_FACTORY_H
#define _DISPLAY_FACTORY_H

class LcdDisplay;
class ConsoleDisplay;

class DisplayFactory {
    DisplayFactory() = default;

public:
    static LcdDisplay* MakeLcdDisplay(int fd);
    static ConsoleDisplay* MakeConsoleDisplay();
};

#endif // _DISPLAY_FACTORY_H
