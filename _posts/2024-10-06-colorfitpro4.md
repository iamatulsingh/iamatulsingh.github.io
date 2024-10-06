---
title: Colorfit pro 4
date: 2024-10-07 00:28:00 +200
categories: [ble, bluetooth, smart-watch, reverse-engineering]
tags: [ble, bluetooth, smart-watch, reverse-engineering]
---

## Colorfit pro 4 (Noisefit) | Reverse Engineering (not a tutorial)

![Banner](/assets/images/noisefit4pro/noisefitpro4.jpg)

## Why I did that?

>I really hate sharing my personal data with any company. That’s why I thought, why not use my old smartwatch to check my health data without connecting to the app (which will save my data on a server)? This way, I can also do some automation using it.
{: .prompt-info }

## Little Introduction

I started working on this by connecting the watch to its app. I began analyzing the BLE connection between them to understand what was happening. When I saw the data, it seemed somewhat complex, so I used jadx to check the code. After a few minutes, I found some functions responsible for communication between the app and the watch. Digging a bit deeper, I discovered .proto files being used to populate the data received from the watch and display it in the app’s UI. The code is dynamic and it can connect to any `noisefit pro 4` watch nearby. I'm not going to share the complete code at the moment but below is a sneak peek.


## Small code example

```python
async def noisefit_4_pro() -> None:
    """Search device and perform operation of getting basic data"""
    limit = 50
    retry = 0
    try:
        cprint.header(f"Searching for noisefit watch ...")
        devices = await discover()
        this_device = None
        if len(devices):
            devices_set = list(set(devices))
            this_device = devices_set[0]
            cprint.info(f"Total noisefit watch found: {len(devices_set)}")
            cprint.info(f"Devices: {devices_set}")
        if this_device is None:
            cprint.error(f"No noisefit watch found. Please make sure your watch is not connected to other device. Exiting!")
            return
        cprint.warning(f"Trying connecting to {this_device.name} {this_device.address} ...")
    except AttributeError as ae:
        cprint.error(f"Failed to connect to Watch. Please check if Watch is not connected to other device.")
        cprint.error(f"{ae}")
        return
    # get basic data
    await get_basic_data(this_device, retry, limit)
```

## Heart Rate

>Heart Rate Calculating on the Watch
{: .prompt-tip }

![Heart Rate](/assets/images/noisefit4pro/noisefitpro4_heart_rate.gif)

## Code in Action

>Code in Action
{: .prompt-tip }

![In Action](/assets/images/noisefit4pro/noisefit4pro_output.gif)

## Final Output

>Final Result
{: .prompt-tip }

![Final Image](/assets/images/noisefit4pro/noisefitpro4_final.jpg)