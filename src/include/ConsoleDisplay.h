#ifndef _CONSOLE_DISPLAY_H
#define _CONSOLE_DISPLAY_H

#include <stdint.h>

#include "Display.h"

class ConsoleDisplay : public Display {
public:
    ConsoleDisplay();

    void Init() override;
    void Reset() override;
    void ClearScreen() override;
    void PrintLine(const char* line) override;
    void Print(const char* line, bool line_feed) override;
    void MoveCursor(int row, int column) override;

    void EchoOn() override;
    void EchoOff() override;

private:
    uint32_t x;
    uint32_t y;
};

#endif // _CONSOLE_DISPLAY_H
