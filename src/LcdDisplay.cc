#include "LcdDisplay.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <termios.h>
#include <curses.h>
#include <syslog.h>
#include <wiringPiI2C.h>

#include <sstream>
#include <fmt/core.h>

#include "Display.h"
#include "I2cController.h"

static const uint8_t REG_LCD = 0x00;
static const uint8_t REG_LCD_RESET = 0x3F;

static const uint8_t LCD_CLEAR_SCREEN = 0x0C;
static const uint8_t LCD_MOVE_CURSOR = 0x1B;

using namespace std;

LcdDisplay::LcdDisplay() {}

LcdDisplay::LcdDisplay(int fd) : i2c_fd(fd), debug(false) {}

void LcdDisplay::Init() {}

bool LcdDisplay::IsReset() {
    int reg_value = wiringPiI2CReadReg8(i2c_fd, REG_LCD_RESET);

    if (reg_value == -1) {
        string errStr =
            fmt::format("Error reading register 0x{:02X} from I2C slave device "
                        "0x{:02X}", REG_LCD_RESET, DEVICE_ADDRESS);

        syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr.c_str());

        return false;
    }

    if (reg_value != 0) {
        if (debug) {
            string debugStr = "LCD Display: Reset detected";

            syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr.c_str());
        }

        return true;
    }

    return false;
}

void
LcdDisplay::Reset() {
    int status = wiringPiI2CWriteReg8(i2c_fd, REG_LCD_RESET, 0x00);

    if (status == -1) {
        string errStr =
            fmt::format("Error writing register 0x{:02X} on I2C slave device "
                        "0x{:02X}", REG_LCD_RESET, DEVICE_ADDRESS);

        syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr.c_str());

        return;
    }

    if (debug) {
        string debugStr = "LCD Display: Reset";

        syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr.c_str());
    }
}

void LcdDisplay::ClearScreen() {
    char str[2];

    str[0] = LCD_CLEAR_SCREEN;
    str[1] = '\0';

    Print(str, false);
}

void LcdDisplay::PrintLine(const char* line) {
    Print(line, false);
}

void LcdDisplay::Print(const char* line, bool line_feed) {
    if (debug) {
        string debugStr = fmt::format("LCD Display: Output '{}'", line);

        syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG,
               debugStr.substr(0, 80).c_str());
    }

    ostringstream cmd;
    string str;
    int i;

    cmd << fmt::format("sudo i2cset -y 1 0x{:02x} 0x{:02x} ", DEVICE_ADDRESS,
                       REG_LCD);

    int len = strlen(line);

    if (len > LCD_SIZE - 1) {
        len = LCD_SIZE - 1;
    }

    for (i = 0; i < len; i++) {
        str = fmt::format("0x{:02x} ", line[i]);
        cmd << str;
    }

    if (line_feed) {
        cmd << "0x0a ";
    }

    cmd << "0x00 i";

    system(cmd.str().c_str());
}

void LcdDisplay::MoveCursor(int row, int column) {
    if (debug) {
        string debugStr =
            fmt::format("LCD Display: Move cursor to row {}, column {}", row,
                        column);

        syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr.c_str());
    }

    string cmd =
        fmt::format("sudo i2cset -y 1 0{:02x} 0x{:02x} 0x{:02x} 0x{:02x} "
                    "0x00 i", DEVICE_ADDRESS, REG_LCD + 1, row, column);

    system(cmd.c_str());

    cmd = fmt::format("sudo i2cset -y 1 0x{:02x} 0x{:02x} 0x{:02x} i",
                      DEVICE_ADDRESS, REG_LCD, LCD_MOVE_CURSOR);

    system(cmd.c_str());
}

void LcdDisplay::EchoOn() {
    // Define a terminal configuration data structure
    termios term;

    // Copy the stdin terminal configuration into term
    tcgetattr(fileno(stdin), &term);

    // Turn on Canonical processing in term
    term.c_lflag |= ICANON;

    // Turn on screen echo in term
    term.c_lflag |= ECHO;

    // Set the terminal configuration for stdin according to term, now.
    tcsetattr(fileno(stdin), TCSANOW, &term);
}

void LcdDisplay::EchoOff() {
    // Define a terminal configuration data structure
    struct termios term;

    // Copy the stdin terminal configuration into term
    tcgetattr(fileno(stdin), &term);

    // Turn off Canonical processing in term
    term.c_lflag &= ~ICANON;

    // Turn off screen echo in term
    term.c_lflag &= ~ECHO;

    // Set the terminal configuration for stdin according to term, now
    tcsetattr(fileno(stdin), TCSANOW, &term);
}

void LcdDisplay::Debug() { debug = true; }
