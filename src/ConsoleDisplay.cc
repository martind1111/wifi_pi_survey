#include "ConsoleDisplay.h"

#include <curses.h>
#include <string.h>

#include <string>

using namespace std;

ConsoleDisplay::ConsoleDisplay() : x(0), y(0) { }

void ConsoleDisplay::Init() {
    initscr();
    cbreak();
}

void ConsoleDisplay::Reset() {}

void ConsoleDisplay::ClearScreen() {
    clear();
}

void ConsoleDisplay::PrintLine(const char* line) {
    Print(line, false);
}

void ConsoleDisplay::Print(const char* line, bool line_feed) {
    int len = strlen(line);

    if (len > LCD_SIZE - 1) {
      len = LCD_SIZE - 1;
    }

    string str = line;

    mvaddstr(y, x, str.substr(0, len).c_str());
    refresh();

    if (line_feed) {
        y += 1;
        x = 0;
    }
}

void ConsoleDisplay::MoveCursor(int row, int column) {
    y = row;
    x = column;
}

void ConsoleDisplay::EchoOn() {
    endwin();
}

void ConsoleDisplay::EchoOff() {
    noecho();
}
