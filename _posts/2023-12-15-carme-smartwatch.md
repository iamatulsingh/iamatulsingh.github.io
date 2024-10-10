---
title: How I Hacked the Lenovo Carme HW25P Smartwatch
date: 2023-12-15 12:00:00 +100
categories: [bluetooth, ble, smart-watch]
tags: [bluetooth, ble, smart-watch]
---


![Banner](/assets/images/carme/carme_banner.jpg)

In this tutorial I am going to tell you how I hacked Lenovo Carme smartwatch using Python3 in less than 100 lines of code and with basic knowledge of BLE (Bluetooth Low Energy). This code has been tested on Ubuntu 18.04. It will not work on Windows. You can find the source code for the same in my Github repository <a href="https://github.com/iamatulsingh/Carme-HW25P?ref=hackernoon.com">here</a>.


![Watch](/assets/images/carme/carme_watch.jpg)

### Prerequisites
Concepts of Object-Oriented Programming and some knowledge of how BLE works.

### What tools I’ve used?

I used `Gatttool` for identifying the correct characteristic to communicate with the device.

### How I hacked?
Before I started to work on this project I had to read about BLE communication, Damn it went bouncer to understand the concept when I read it first but then after reading couple of times I thought I know it very well. But did I? Lets find it out.
I fired up `Gatttool` to search all UUIDs of this device and got the list which I'm showing in below image.

![Characteristics](/assets/images/carme/characteristics.png)

Now the questions was what I want to do and what I need for that. I started with the basic things first and that is battery level. I used nrf connect to find the handle of battery level which is 0x0030 and in response I got “X” and i was like …

![Characteristics](/assets/images/carme/minion_what.gif)

I searched little bit and found response of BLE devices. So it was a 1 byte string which is ASCII equivalent of 0x58. So when we unpack the byte value we will get 88 and finally which is battery level data. So lets check the code that I wrote in python below.

```python
def battery_data(self):
    self.battery_char = self.readCharacteristic(int(UUIDS.BATTERY_INFO_HND, 16))
    self.battery_level = struct.unpack("<B", self.battery_char)[0]
    self._log.info(f"Battery Level: {self.battery_level}")
```

Now after that I become hungry for Heart Rate Monitor. I started to dig into UUIDs and I am really lazy to do these things then I suddenly realized that I have learned previously that UUIDs are universal so there must be some thing related to heart rate. I go through the UUIDs of HW25P and found that there are no service available for Heart Rate Control (HRC). I then think of just to subscribe the HRM notify handle and retrieve data from it. So i wrote a code with the help of examples of bluepy to subscribe to notify handle. For subscribing I sent 2 byte data \x01\x00to notify sensor to turn it on. You can find the code below.

```python
def heart_rate_data(self):
    self.hr_countdown = None
    try:
        service, = [s for s in self.getServices() if s.uuid == self.hrmid]
        _ = service.getCharacteristics(forUUID=str(self.hrmmid))

        desc = self.getDescriptors(service.hndStart, service.hndEnd)
        d, = [d for d in desc if d.uuid == self.cccid]

        self.writeCharacteristic(d.handle, b'\x01\x00')

        def print_hr(cHandle, data):
            self.hr_countdown = time.perf_counter()
            self._log.info(data[1])

        self.delegate.handleNotification = print_hr
        self._log.info("Waiting for Heart Rate notification ...")

        while True:
            try:
                if self.hr_countdown and (time.perf_counter() - self.hr_countdown) >= 3:
                    self._log.info("HRM completed")
                    break
                else:
                    self.waitForNotifications(3.)

            except KeyboardInterrupt:
                self._log.info("HRM operation closed by user")
                self.writeCharacteristic(d.handle, b'\x00\x00')
                break

    except BTLEException as btlE:
        self._log.error(f"{btlE}")
```

Here is the class I made and inherit Bluepy.btle class Peripheral to make a working code.


```python
class HW25P(Peripheral):

    def __init__(self, mac_address, timeout=0.5, isSecure=False, debug=False):
        FORMAT = '%(asctime)-15s %(name)s (%(levelname)s) > %(message)s'
        logging.basicConfig(format=FORMAT)
        log_level = logging.WARNING if not debug else logging.DEBUG
        self._log = logging.getLogger(self.__class__.__name__)
        self._log.setLevel(log_level)

        self._log.info('Connecting to ' + mac_address)
        if isSecure:
            Peripheral.__init__(self, mac_address)
        else:
            Peripheral.__init__(self, mac_address)

        self.cccid = AssignedNumbers.client_characteristic_configuration
        self.hrmid = AssignedNumbers.heart_rate
        self.hrmmid = AssignedNumbers.heart_rate_measurement

        self._log.info('Connected')

        self.timeout = timeout
        self.mac_address = mac_address
```

And finally you can check the working code screenshot below.

![HeartRate](/assets/images/carme/heart_rate.png)

Hope you like this tutorial. Do share your thoughts and feedback with me. If you find any issue then do let me know to overcome that.
