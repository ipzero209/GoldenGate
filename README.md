# GoldenGate

This software is meant to run alongside Panorama installations running PAN-OS 8.1 or later. It provides a method for ingestion device monitoring data for managed devices running versions of PAN-OS earlier than 8.1.

## Dependencies

  1. Linux: This project was tested on Ubuntu, but will work on any modern Linux distribution. It does use initd for service management, but you can adapt it to use systemd as needed.
  2. Python Modules:  
    A. Python Module - requests: This is a widely used module for implementing HTTP requests. Information can be found here:  
      i. [Github repo](https://github.com/requests/requests)  
      ii. [Docs](http://docs.python-requests.org/en/master/)  
    B. Python Module - xml.etree.ElementTree: This module is included with most installations of Python.  
    C. Python Module - json: This module is included with most installations of Python.  
    D. Python Module - os: This module is included with most installations of Python.  
    E. Python Module - ast: This module is included with most installations of Python.  
    F. Python Module - re: This module is included with most installations of Python.  
    G. Python Module - logging: This module is included with most installations of Python.  
    H. Python Module - shelve: This module is included with most installations of Python.  
    I. Python Module - threading: This module is included with most installations of Python.  
  3. SSH Access:  
      As of PAN-OS 8.0, management interfaces on Panorama and managed firewalls no longer supports connections using TLS1.0 by default. In order for this script to work, you will need to either:  
        1. Apply an SSL/TLS service profile which explicitly allows TLS1.0 to the management interfaces of Panorama and the managed firewalls, or  
        2. Upgrade the version of open SSL on the host where the script will be running to version 1.0.2
  
  
## Requirements:
  
  1. Python 2.7
  2. Connectivity between the host running the script and the management interface of Panorama/managed firewalls on TCP/443.
  **NOTE: This script does not currently support gathering data from firewalls via dataplane interfaces (firewalls that connect to Panorama using a service route).


## Preparation

This script uses the XML API to gather device monitoring data from the firewalls and to feed that data into Panorama. It is recommended that a unique API admin account be created specific for the script. There are two options for creating this API user account:
  1. Create the account as a 'superreader'
  2. Create a custom admin role. If you choose to create an admin role, the settings need to include:
    A. Type (for Panorama): Panorama
    B. Access: XML API - Operational Commands

## Installation

1. Download a zip archive of the project
2. Transfer to the host that will be running the script
3. Unpack the archive (this can be in a temporary location)
4. Run the setup using 'sudo ./shim_setup.py'
5. Follow the on screen prompts
6. Verify that the service is running:
  A. 'sudo service shim_svc status'
  B. 'ps -ef | grep python' - you should see a process for pan_shim.py

## Configuration

The conf file is located at /etc/pan_shim/pan_shim.conf. There are currently two supported options:
  1. LEVEL: this is a tuple that dictates the logging level. Values can be one of:  
    A. debug  
    B. info  
    C. warning  
    D. error  
    E. critical  
  2. EXLCUDE: This is a tuple that will allow you to exclude certain serial numbers from being polled (one entry per line). Example:  
      EXCLUDE:000013846783  
      EXCLUDE:003210045732  
  3. Restart the service for changes to take effect.
    A. 'sudo service shim_svc restart'
    
    
    

