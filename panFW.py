class Device:
    """Devices are managed from Panorama and have the following attributes:
    ser_num: Serial number of the manaaged device.
    hostname: Host name of the managed device.
    model: Model numer of the managed device.
    family: Model family of the managed device.
    os_ver: Version of PAN-OS running on the managed device.
    mgmt_ip: Management IP of the managed device.
    """


    def __init__(self, ser_num, mgmt_ip, os_ver, family, is_ha='no', ha_peer=None, ha_state=None):
        self.ser_num = ser_num
        self.mgmt_ip = mgmt_ip
        self.os_ver = os_ver
        self.family = family
        if is_ha == 'no':
            self.ha_peer = "No Peer"
            self.ha_state = "No State"
