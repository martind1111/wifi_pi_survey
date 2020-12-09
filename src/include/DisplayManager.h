#ifndef _DISPLAY_MANAGER_H
#define _DISPLAY_MANAGER_H

#include <list>
#include <vector>
#include <memory>

class ApplicationContext;
class Display;
class LcdDisplay;
class NetworkDiscovery;

using DisplayPtr = std::shared_ptr<Display>;

class ApplicationContext;
class I2cController;
class LcdDisplay;

class DisplayManager {
public:
    DisplayManager(const ApplicationContext* context,
                   const I2cController* controller);

    void Init();
    void ClearScreen();
    void PrintLine(const char* line);
    void Print(const char* line, bool line_feed);
    bool IsLcdReset();
    void Reset();
    void MoveCursor(int row, int column);
    void EchoOn();
    void EchoOff();

private:
    LcdDisplay* GetLcdDisplay();

    bool debug_lcd_display;
    bool interactive;
    const I2cController* i2c_controller;
    LcdDisplay* lcd_display;

    std::list<DisplayPtr> displays;
};

#endif // _DISPLAY_MANAGER_H
