#ifndef _LCD_DISPLAY_H
#define _LCD_DISPLAY_H

#include "Display.h"

class LcdDisplay : public Display {
    LcdDisplay(); // Private constructor

public:
    LcdDisplay(int fd);

    void Init() override;
    void Reset() override;
    bool IsReset();
    void ClearScreen() override;
    void PrintLine(const char* line) override;
    void Print(const char* line, bool line_feed) override;
    void MoveCursor(int row, int column) override;

    void EchoOn() override;
    void EchoOff() override;

    void Debug();

private:
    int i2c_fd;
    bool debug;
};

#endif // _LCD_DISPLAY_H
