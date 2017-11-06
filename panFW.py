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
        self.is_ha = is_ha
        if self.is_ha == 'no':
            self.ha_peer = "No Peer"
            self.ha_state = "No State"
        else:
            self.ha_peer = ha_peer
            self.ha_state = ha_state


    def prinfo(self):
        print "S/N:\t{}".format(self.ser_num)
        print "IP:\t{}".format(self.mgmt_ip)
        print "SW-Version:\t{}".format(self.os_ver)
        print "Model Family:\t{}".format(self.family)
        print "Is HA:\t{}".format(self.is_ha)
        if self.is_ha == 'yes':
            print "Peer:\t{}".format(self.ha_peer)
            print "HA State:\t{}".format(self.ha_state)