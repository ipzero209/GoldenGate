#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
import json
import panFW
import ast

from requests.packages.urllib3.exceptions import InsecureRequestWarning


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

##########################################################
#
#       MP CPU
#
##########################################################

def mpCPU(fw, api_key, u_dict):
    xpath = "<show><system><state><filter>sys.monitor.s*.mp.exports</filter></stat" \
            "e></system></show>"
    prefix = "https://{}/api/?".format(fw.mgmt_ip)
    mp_cpu_req = requests.get(prefix + xpath + api_key, verify=False)
    mp_cpu_xml = et.fromstring(mp_cpu_req.content)
    mp_cpu_text = mp_cpu_xml.find('./result').text
    mp_cpu_text = mp_cpu_text[mp_cpu_text.find('{'):]
    mp_cpu_text = mp_cpu_text.replace('\'', '"')
    mp_cpu_text = mp_cpu_text.replace(', }', ' }')
    mp_cpu_json = json.loads(mp_cpu_text)
    u_dict['trend']['m'] = int(mp_cpu_json['cpu']['1minavg'])
    return u_dict

##########################################################
#
#       MP MEM
#
##########################################################

def mpMem(fw, api_key, u_dict):
    xpath = "<show><system><state><filter>resource.s*.mp.memory</filter></state></" \
            "system></show>"
    prefix = "https://{}/api/?".format(fw.mgmt_ip)
    mp_mem_req = requests.get(prefix + xpath + api_key, verify=False)
    mp_mem_xml = et.fromstring(mp_mem_req.content)
    mp_mem_text = mp_mem_xml.find('./result').text
    mp_mem_text = mp_mem_text[mp_mem_text.find('{'):]
    mp_mem_text = mp_mem_text.replace('\'', '"')
    mp_mem_text = mp_mem_text.replace(', }', ' }')

    match_begin = re.compile(': (?=[0-9a-fA-Z])')
    match_end = re.compile(',(?= ")')
    match_end_2 = re.compile(' (?=})')

    num_quote = re.compile('(?=, )')
    mp_mem_text = re.sub(match_begin, ': "', mp_mem_text)
    mp_mem_text = re.sub(match_end_2, '"', mp_mem_text)
    mp_mem_text = re.sub(num_quote, '"', mp_mem_text)
    mp_mem_json = json.loads(mp_mem_text)
    used_mem_hex_str = mp_mem_json['used']
    used_mem_int = int(used_mem_hex_str, 16)
    total_mem_hex_str = mp_mem_json['size']
    total_mem_int = int(total_mem_hex_str, 16)
    used_mem_pct = (float(used_mem_int) / float(total_mem_int)) * 100  # TODO: round if you have time
    u_dict['trend']['mm'] = used_mem_pct
    return u_dict