class Device:
    """Devices are managed from Panorama and have the following attributes:
    ser_num: Serial number of the manaaged device.
    hostname: Host name of the managed device.
    model: Model numer of the managed device.
    family: Model family of the managed device.
    os_ver: Version of PAN-OS running on the managed device.
    mgmt_ip: Management IP of the managed device.
    """


    def __init__(self, h_name, ser_num, mgmt_ip, os_ver, family, is_ha='no', ha_peer=None, ha_state=None):
        self.h_name = h_name
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
        p_string = ""
        p_string = p_string + "Hostname:\t{}\n".format(self.h_name)
        p_string = p_string + "S/N:\t{}\n".format(self.ser_num)
        p_string = p_string + "IP:\t{}\n".format(self.mgmt_ip)
        p_string = p_string + "SW-Version:\t{}\n".format(self.os_ver)
        p_string = p_string + "Model Family:\t{}\n".format(self.family)
        p_string = p_string + "Is HA:\t{}\n".format(self.is_ha)
        if self.is_ha == 'yes':
            p_string = p_string + "Peer:\t{}\n".format(self.ha_peer)
            p_string = p_string + "HA State:\t{}\n".format(self.ha_state)
        return p_string