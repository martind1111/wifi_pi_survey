#ifndef _I2C_CONTROLLER_H
#define _I2C_CONTROLLER_H

#include <stdint.h>

static uint8_t REG_STATUS_LED = 0x41;
static uint8_t REG_EXT1_LED = 0x43;
static uint8_t REG_EXT2_LED = 0x44;

static const uint8_t REG_BUTTON = 0x42;

static const uint8_t BUTTON_STATUS_SHORT = 1;
static const uint8_t BUTTON_STATUS_LONG = 2;

static const uint8_t DEVICE_ADDRESS = 0x50;

class I2cController {
public:
    I2cController() : oper(false), fd(0) { }

    void Init();

    bool IsOperational() const {
        return oper;
    }

    int GetFileDescr() const {
        return fd;
    }

private:
    bool oper;

    int fd;
};

#endif // _I2C_CONTROLLER_H
