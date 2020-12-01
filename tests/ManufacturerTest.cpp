#include <gtest/gtest.h>

#include <netinet/ether.h>

#include "HardwareHelper.h"

// Test the manufacturer API.
TEST(ManufacturerTest, GetManufacturer) {
    ether_addr addr = { 0x00, 0x03, 0x93, 0x01, 0x02, 0x03 };
    const char* manuf = HardwareHelper::GetManufacturer(&addr);

    EXPECT_STREQ(manuf, "Apple");
}
