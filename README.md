# Wifi Pi Survey #

Project documentation: http://mdubuc.freeshell.org/WifiPiSurvey

# Requirements #

The following packages must be installed on the Raspberry Pi to be able to build this project:

```
sudo apt-get install cmake
sudo apt-get install libsqlite3-dev
sudo apt-get install libgps-dev
sudo apt-get install libpcap-dev
sudo apt-get install libpcre-dev
sudo apt-get install libgtest-dev
sudo apt-get install wireshark
```

# Build instructions #

```
mkdir build
cd build
cmake ..
make
```

# Enabling I2C #

```
sudo vi /etc/modules
```

Add these lines:
i2c-bcm2708
i2c-dev

```
sudo vi /etc/modprobe.d/raspi-blacklist.conf
```

Comment blacklist i2c-bcm2708

```
sudo apt-get install python-smbus i2c-tools
```

Reboot
```
sudo reboot
```

```
sudo i2cdetect -y 1

sudo i2cget -y 1 0x2a 0x00

sudo i2cset -y 1 0x2a 0x00 0x01
```

# Enabling GPIO #

```
sudo apt-get install wiringpi
```

```
gpio -g mode 23 out
gpio -g write 23 1
gpio -g write 23 0
```
or
```
gpio mode 4 out
gpio write 4 1
gpio write 4 0
```

# Running kismet #

Download kismet (kismet-2013-03-R1b.tar.gz)

```
sudo apt-get install libncurses
sudo apt-get install ncurses
sudo apt-get install libncurses5
sudo apt-get install libncurses-dev
sudo apt-get install libpcap
sudo apt-get install libpcap-dev
sudo apt-get install libnl-dev
./configure
sudo make install
sudo vi /usr/local/etc/kismet.conf

lsusb
```

Kill ifplugd used to manage wlan0 interface
```
ps alwwx | grep ifplugd


sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
```

Install manuf file from wireshark distribution to /etc/manuf

/var/log/kismet

Edit:
/etc/default/ifplugd
/etc/network/interfaces

# System configuration #

Modified /etc/default/gpsd to get gpsd loaded at startup:
START_DAEMON="true"
GPSD_OPTIONS="/dev/ttyUSB0"

To prevent system from hotplugging wlan0:

/etc/network/interfaces:
Comment out allow-hotplug wlan0

/etc/default/ifplugd:
Change INTERFACES from auto to lis of interfaces to hotplug (eth0, lo)

Installed wscand in /etc/init.d

sudo chmod 0755 /etc/init.d/wscand
sudo update-rc.d wscand defaults

# Executing daemon #

How to launch the Wifi Pi survey daemon on the Rapsberry Pi:

```
sudo ./wscand -i wlan0 -e -v 4 -p 100000 -o wscan.log
```
