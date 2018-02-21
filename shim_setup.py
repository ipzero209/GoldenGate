#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import getpass
import shelve
import os
import logging
import argparse
import sys

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

if os.getuid() != 0:
    print "Not running with sudo. Please re-start set up using sudo ./shim_setup.py"
    exit(1)

os.system('mkdir /var/log/pan')

logger = logging.getLogger("setup")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler("/var/log/pan/shim_setup.log")
formatter = logging.Formatter('%(asctime)s %(name)s\t%(levelname)s:\t\t%(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

def upCheck(ip_addr):
    """Checks basic connectivity to the target device"""
    status = os.system('ping -c 1 {}'.format(ip_addr))
    return status

def getKey():
    """Used to fetch the API key for use in polling devices"""
    pano_ip = raw_input("Enter the IP address of your Panorama: ")
    user = raw_input("Enter the API username. NOTE: This user must exist and have the proper permissions on both " \
                     "Panorama and all Panorama managed firewalls.\n\nUsername: ")
    passwd = getpass.getpass("\nEnter the password for the API user: ")
    key_string = "https://" + pano_ip + "/api/?type=keygen&user=" + user + "&password=" + passwd
    pano_status = upCheck(pano_ip)
    if pano_status != 0:
        path = os.popen("tracepath -l 1460 {}".format(pano_ip)).read()
        logger.warning("Cannot ping Panorama. Path is\n\n{}".format(path))
        print "Cannot ping Panorama from here. Path is\n\n{}".format(path)
    try:
        key_request = requests.get(key_string, verify=False)
    except Exception as e:
        logger.critical("Unable to reach Panorama on port 443. Error is:\n\n{}".format(e))
        print "Unable to reach Panorama on port 443. Error is:\n\n{}".format(e)
    key_xml = et.fromstring(key_request.content)
    if key_request.status_code != 200:
        err_node = key_xml.find('./result/msg')
        logger.critical('Error retrieving API key from {}: {}'.format(pano_ip, err_node.text))
        return 1
    key_node = key_xml.find('./result/key')
    logger.info("API key successfully retrieved from {}.".format(pano_ip))
    saveInfo('pano_ip', pano_ip)
    logger.info('Panorama IP saved to data file.')
    saveInfo('api_key', key_node.text)
    logger.info('API key saved to data file.')
    return 0

def saveInfo(key_str, data):
    """Used to shelve the API key for later use"""
    logger.info("Saving API key.")
    s_data = shelve.open('/etc/pan_shim/data')
    s_data[key_str] = data
    s_data.close()
    logger.info("{} saved to data file}".format(key_str))
    return

def prepService():
    """Moves files to the appropriate directories and sets the correct permissions"""
    logger.info("Copying shim_svc to /etc/init.d")
    shim_cp = os.system("cp ./shim_svc /etc/init.d/")
    py_list = ['pan_shim.py', 'panFW.py', 'Metrics.py', 'shim_setup.py']
    if shim_cp != 0:
        logger.critical("Could not copy service file to /etc/init.d. Are we "
                         "running with sudo?")
        return 1
    logger.info("Setting permissions on shim_svc")
    shim_perm = os.system("chmod 755 /etc/init.d/shim_svc")
    if shim_perm != 0:
        logger.critical("Could not set permissions on /etc/init.d/shim_svc")
        return 1
    logger.info("Copying conf file to /etc/pan_shim")
    os.system("cp ./pan_shim.conf /etc/pan_shim/")
    for file in py_list:
        logger.info("Copying {} to /usr/local/bin".format(file))
        py_copy = os.system("cp {} /usr/local/bin/".format(file))
        if py_copy != 0:
            logger.critical("Failed to copy {} to /usr/local/bin".format(file))
            return 1
        logger.info("Setting permissions on {}".format(file))
        py_perm = os.system("chmod 755 /usr/local/bin/{}".format(file))
        if py_perm != 0:
            logger.critical("Failed to set permissions on {}".format(file))
            return 1
    logger.info("Setting up log file.")
    log_touch = os.system('touch /var/log/pan/shim.log')
    if log_touch != 0:
        logger.warning("Failed to create shim log file. May need to manually set"
                       "permissions after setup")
    logger.info("Setting permissions on him log file")
    log_perm = os.system("chmod 766 /var/log/pan/shim.log")
    if log_perm != 0:
        logger.warning("Failed to set permissions on shim log file. Please manually"
                       "set 766 permissions after setup is complete, then restart"
                       "the service.")
    logger.info("Updating rc.d")
    update_rc = os.system("update-rc.d shim_svc defaults")
    if update_rc != 0:
        logger.critical("Failed to update rc.d")
        return 1
    return 0

def svcStart():
    """Starts the service"""
    logger.info("Attempting to start the service")
    svc_start = os.system("service shim_svc start")
    if svc_start != 0:
        logger.critical("Failed to start shim_svc")
        return 1
    svc_status = os.popen("service shim_svc status").read()
    if "(exited)" in svc_status:
        logger.critical("shim_svc exited. Please start service manually using "
                        "'sudo service shim_svc start")
        print "the shim service failed to start automatically. Please start the " \
              "service manually using 'sudo service shim_svc start"
    elif "(running)" in svc_status:
        logger.info("shim_svc started successfully")
    return 0

def svcStop():
    """Stops the service"""
    logger.info("Attempting to stop the service")
    svc_stop = os.system("service shim_svc stop")
    if svc_stop != 0:
        logger.critical("Failed to stop shim_svc")
        return 1
    return 0

def removeFiles():
    """Deletes pan shim related files"""
    os.system('rm -rf /etc/pan_shim')
    # os.system('rmdir /etc/pan_shim')
    os.system('rm -rf /var/log/pan')
    # os.system('rmdir /var/log/pan')
    os.system('rm -f /etc/init.d/shim_svc')
    os.system('rm -f /usr/local/bin/Metrics.py')
    os.system('rm -f /usr/local/bin/Metrics.pyc')
    os.system('rm -f /usr/local/bin/panFW.py')
    os.system('rm -f /usr/local/bin/panFW.pyc')
    os.system('rm -f /usr/local/bin/pan_shim.py')
    os.system('rm -f /usr/local/bin/shim_setup.py')
    return

def main():

    logger.info('Created log directory.')


    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", "--install", help="Installs pan shim", action="store_true")
    group.add_argument("-r", "--renew", help="Updates the stored API key", action="store_true")
    group.add_argument("-u", "--uninstall", help="Uninstalls pan shim", action="store_true")
    args = parser.parse_args()
    if len(sys.argv) < 2:
        parser.print_help()
        parser.exit()
        exit(1)



    if args.install:
        print "Welcome to pan_shim. This set up will guide you through setting up the shim service."
        os.system('mkdir /etc/pan_shim/')
        api_key = getKey()
        if api_key == 1:
            logger.critical("Error getting the API key")
            exit(1)
        prep = prepService()
        if prep == 1:
            logger.critical("Critical error in service set up. See log for details.")
            exit(1)
        s_start = svcStart()
        if s_start == 1:
            logger.critical("Critical error when starting the service. See log for "
                            "details.")
        logger.info("Setup complete.")
        print "Setup complete"
        exit(0)
    elif args.renew:
        if not os.path.isfile('/etc/pan_shim/data'):
            logger.info('No data file found. Please check the location of the '
                        'data file. The file name is \'data\' and it should be'
                        'located at /etc/pan_shim/')
            print "Error opening the data file. Please see the setup log for more" \
                  "details."
        stop = svcStop()
        if stop == 1:
            logger.critical("Failed to stop service. Exiting now.")
            print "There was an issue stopping the service. Please see the setup" \
                  " log for more details."
            exit(1)
        k_status = getKey()
        if k_status != 0:
            logger.critical('There was an issue renewing the API key.')
            exit(1)
        start = svcStart()
        if start != 0:
            logger.warning('Error starting the service.')
            exit(1)
        exit(0)
    elif args.uninstall:
        confirm = raw_input("This will uninstall pan shim from your system."
                            "Are you sure? (y/N): ")
        if confirm == ("" or "n" or "N" or "no" or "No" or "NO"):
            logger.info("Cancelling uninstall at user request.")
            exit(0)
        elif confirm == ("y" or "Y" or "Yes" or "yes"):
            print "Proceding with uninstall."
            logger.warning("Uninstall confirmed.")
        else:
            print "Please enter y or n. Exiting now."
            logger.warning("Invalid choice for confirmation prompt. Exiting.")
            exit(0)
        stop = svcStop()
        if stop == 1:
            logger.critical("Failed to stop service. Please manually stop the "
                            "service after uninstallation is complete.")
        removeFiles()




if __name__ == '__main__':
    main()