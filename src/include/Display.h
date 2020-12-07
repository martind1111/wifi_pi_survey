#ifndef _DISPLAY_H
#define _DISPLAY_H

#include <string>

static const size_t MAX_LINE_LENGTH = 24;
static const size_t LCD_SIZE = 64;

class Display {
public:
public:
    virtual void Init() = 0;
    virtual void Reset() = 0;
    virtual void ClearScreen() = 0;
    virtual void PrintLine(const char* line) = 0;
    virtual void Print(const char* line, bool line_feed) = 0;
    virtual void MoveCursor(int row, int column) = 0;

    virtual void EchoOn() = 0;
    virtual void EchoOff() = 0;
};

#endif // _DISPLAY_H
