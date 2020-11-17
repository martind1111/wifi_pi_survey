#include <gtest/gtest.h>

#include "manufacturer.h"

// Test the manufacturer API.
TEST(ManufacturerTest, GetManufacturer) {
    struct ether_addr addr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const char* manuf = getManufacturer(addr);
    
    EXPECT_EQ(manuf, 'Apple');
}
