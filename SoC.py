from rcm_backend import RCMHax

RCM_V1_HEADER_SIZE = 116
RCM_V35_HEADER_SIZE = 628
RCM_V40_HEADER_SIZE = 644
RCM_V4P_HEADER_SIZE = 680

class T20(RCMHax):
    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False):
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
        self.RCM_HEADER_SIZE  = RCM_V1_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000A000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40005000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR
        self.STACK_SPRAY_END     = self.RCM_PAYLOAD_ADDR - 420 # exact position is known.
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 4

        self.STACK_SPRAY_END     = self.STACK_END # spray whole stack
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END -0x200 # 512 Byte should be enough? #0x40009E40

        # The address where the user payload is expected to begin.
        # A reasonable offset allows Intermezzo to grow without problems
        self.PAYLOAD_START_OFF  = 0xE40

        RCMHax.__init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False)

class T114(RCMHax):
    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False):
        self.RCM_HEADER_SIZE  = RCM_V35_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000E000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40008000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR
        self.STACK_SPRAY_END     = self.STACK_END
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x200 # 512 Byte should be enough? #0x40009E40

        # The address where the user payload is expected to begin.
        # A reasonable offset allows Intermezzo to grow without problems
        self.PAYLOAD_START_OFF  = 0xE40

        RCMHax.__init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False)

class T124(RCMHax):

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False):
        self.RCM_HEADER_SIZE  = RCM_V40_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000E000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40008000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR
        self.STACK_SPRAY_END     = self.STACK_END
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x200 # Might not be enough

        # The address where the user payload is expected to begin.
        # A reasonable offset allows Intermezzo to grow without problems
        self.PAYLOAD_START_OFF  = 0xE40

        RCMHax.__init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False)

class T132(RCMHax):

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False):
        self.RCM_HEADER_SIZE  = RCM_V40_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000F000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40008000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR
        self.STACK_SPRAY_END     = self.STACK_END
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x200 # Might not be enough

        # The address where the user payload is expected to begin.
        # A reasonable offset allows Intermezzo to grow without problems
        self.PAYLOAD_START_OFF  = 0xE40

        RCMHax.__init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False)

class T210(RCMHax):

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False):
        self.RCM_HEADER_SIZE  = RCM_V4P_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x40010000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40009000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR  
        self.STACK_SPRAY_END     = self.STACK_END
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x200 # Might not be enough

        # The address where the user payload is expected to begin.
        # A reasonable offset allows Intermezzo to grow without problems
        self.PAYLOAD_START_OFF  = 0xE40

        RCMHax.__init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False)
