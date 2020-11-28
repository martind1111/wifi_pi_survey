# Wifi Pi Survey #

Project documentation: http://mdubuc.freeshell.org/WifiPiSurvey

# Requirements #

The fmt module must be built and installed from source.
```
git clone https://github.com/fmtlib/fmt.git && cd fmt

mkdir _build && cd _build
cmake ..

make -j$(nproc)
sudo make install
```
Once fmt is built and installed, the following packages must be installed on
the Raspberry Pi to be able to build this project:
```
sudo apt-get install cmake sqlite3 libsqlite3-dev gpsd libgps-dev libpcap-dev libpcre3-dev libgtest-dev wireshark
```

# Build instructions #

```
mkdir build
cd build
cmake ..
make
sudo make install
```

# Enabling I2C #

To enable I2C, follow instructions on this page:
https://www.raspberrypi-spy.co.uk/2014/11/enabling-the-i2c-interface-on-the-raspberry-pi/

Here is a summary of the instructions on that page. Run raspi-config to enable
I2C interface:
```
sudo raspi-config
```

Select Interface Options menu

Select I2C menu

Enable I2C

Reboot
```
sudo reboot
```

Install utilities:
```
sudo apt-get install python-smbus i2c-tools
```

Reboot
```
sudo reboot
```

To verify if I2C module is loaded:
```
lsmod | grep i2c_
```
Module i2c_bcm2708 should appear in this list.

Test I2C:

To see where sensor is connected (Model A, B Rev 2 or B+):
```
sudo i2cdetect -y 1
```
Use 0 instead of 1 for Model B Rev 1.

To retrieve and change register value:
```
sudo i2cget -y 1 0x2a 0x00

sudo i2cset -y 1 0x2a 0x00 0x01
```

# Enabling GPIO #

```
sudo apt-get install wiringpi
```

To test out GPIO:
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

# Enabling GPS #

Enable the gpsd service:
```
sudo systemctl enable gpsd
sudo systemctl start gpsd
```

To verify that GPS daemon is running and producing output:
```
stty -F /dev/ttyXXX ispeed 4800 && cat </dev/ttyXXX
```
Where XXX is likely to be USB0 (check that the GPS device is listed with lsusb
command).


# Configuring Wifi interface #

to bring wlan0 interface in monitor mode at startup, create file
/etc/network/interfaces.d/wlan0 with the following content:
```
#/etc/network/interfaces.d/wlan0
auto wlan0
iface wlan0 inet manual
  wireless-mode monitor
```

To manually set the wlan0 interface to monitor mode, issue the following
commands:
```
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
```

# Installing wscand as a service #

To install wscand as a service:

```
sudo cp wscand /etc/init.d
sudo chmod 0755 /etc/init.d/wscand
sudo update-rc.d wscand defaults
```

# Executing daemon #

How to launch the Wifi Pi survey daemon on the Rapsberry Pi:

```
sudo ./wscand -i wlan0 -e -v 4 -p 100000 -o wscand.log
```

# Installing and configuring kismet #

Download kismet (kismet-2013-03-R1b.tar.gz)

```
sudo apt-get install libncurses \
    curses \
    libncurses5 \
    libncurses-dev \
    libpcap \
    libpcap-dev \
    libnl-dev
./configure
sudo make install
sudo vi /usr/local/etc/kismet.conf
```
