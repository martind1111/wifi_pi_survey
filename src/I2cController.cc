#include "I2cController.h"

#include <wiringPiI2C.h>

void
I2cController::Init() {
    fd = wiringPiI2CSetup(DEVICE_ADDRESS);

    int status = wiringPiI2CReadReg8(fd, REG_BUTTON);

    oper = status != -1;
}
