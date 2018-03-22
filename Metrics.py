#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
import json
import os
import panFW
import ast
import re
import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



logger = logging.getLogger(__name__)


formatter = logging.Formatter('%(asctime)s  %(module)s:%(levelname)s:%(funcName)s:\t%(message)s')


file_handler = logging.FileHandler('/var/log/pan/shim.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


if os.path.isfile('/etc/pan_shim/pan_shim.conf'):
    c_file = open('/etc/pan_shim/pan_shim.conf', 'r')
    for line in c_file:
        line = line.split(":")
        logging_level = line[1].strip('\n')
else:
    """Set defaults for all options"""
    logger.setLevel(logging.ERROR)
if logging_level == "debug":
    logger.setLevel(logging.DEBUG)
elif logging_level == "info":
    logger.setLevel(logging.INFO)
elif logging_level == "warning":
    logger.setLevel(logging.WARNING)
elif logging_level == "error":
    logger.setLevel(logging.ERROR)
elif logging_level == "critical":
    logger.setLevel(logging.CRITICAL)
else:
    logger.setLevel(logging.ERROR)









##########################################################
#
#       MP CPU
#
##########################################################

def mpCPU(fw, api_key, u_dict):
    xpath = "<show><system><state><filter>sys.monitor.s*.mp.exports</filter></stat" \
            "e></system></show>&key="
    prefix = "https://{}/api/?type=op&cmd=".format(fw.mgmt_ip)
    mp_cpu_req = requests.get(prefix + xpath + api_key, verify=False)
    mp_cpu_xml = et.fromstring(mp_cpu_req.content)
    logger.debug("MP CPU string for {}, S/N {}:\n{}".format(fw.h_name, fw.ser_num, mp_cpu_req.content))
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
            "system></show>&key="
    prefix = "https://{}/api/?type=op&cmd=".format(fw.mgmt_ip)
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

##########################################################
#
#       DP CPU
#
##########################################################


def dpCPU(fw, api_key, u_dict):
    xpath = "<show><system><state><filter>sys.monitor.s*.dp*.exports</filter></sta" \
            "te></system></show>&key="
    prefix = "https://{}/api/?type=op&cmd=".format(fw.mgmt_ip)
    dp_cpu_req = requests.get(prefix + xpath + api_key, verify=False)
    dp_cpu_xml = et.fromstring(dp_cpu_req.content)
    dp_cpu_text = dp_cpu_xml.find('./result').text
    dp_cpu_text = dp_cpu_text.split('\n')

    # Slot/DP match criteria
    match_dp_slot = re.compile('(?<=monitor\.)(s.*)(?=\.dp)')
    match_dp_dp = re.compile('(?<=\.)(dp.*)(?=\.exports)')

    d_cpu_list = []
    for line in dp_cpu_text:
        if line == "":
            break
        label = line[:line.find('{')]
        slot_num = re.search(match_dp_slot, label).group(0)
        dp_num = re.search(match_dp_dp, label).group(0)
        line = line[line.find('{'):]
        line = line.replace('\'', '"')
        line = line.replace(', }', ' }')
        j_line = json.loads(line)
        if j_line:
            if slot_num not in u_dict['trend']['slot']:
                u_dict['trend']['slot'][slot_num] = {}
            if dp_num not in u_dict['trend']['slot'][slot_num]:
                u_dict['trend']['slot'][slot_num][dp_num] = {}
            u_dict['trend']['slot'][slot_num][dp_num]['d'] = int(j_line['cpu']['1minavg'])
            d_cpu_list.append(int(j_line['cpu']['1minavg']))
    dcpu_avg = float(sum(d_cpu_list)) / float(len(d_cpu_list))
    u_dict['trend']['d'] = dcpu_avg
    return u_dict

##########################################################
#
#       Session Info
#
##########################################################


def sessionInfo(fw, api_key, u_dict):
    xpath = "<show><system><state><filter>sw.mprelay.s*.dp*.stats.session</filter>" \
            "</state></system></show>&key="
    prefix = "https://{}/api?type=op&cmd=".format(fw.mgmt_ip)

    # Slot/DP match criteria
    match_session_slot = re.compile('(?<=mprelay\.)(s.*)(?=\.dp)')
    match_session_dp = re.compile('(?<=\.)(dp.*)(?=\.stats)')

    session_req = requests.get(prefix + xpath + api_key, verify=False)
    session_xml = et.fromstring(session_req.content)
    session_text = session_xml.find('./result').text
    session_text = session_text.split('\n')

    for line in session_text:
        if line == "":
            break
        label = line[:line.find('{')]
        session_slot_number = re.search(match_session_slot, label).group(0)
        session_dp_number = re.search(match_session_dp, label).group(0)
        line = line[line.find('{'):]
        line = line.replace('\'', '"')
        line = line.replace(', }', ' }')
        j_line = json.loads(line)
        t_total = 0
        c_total = 0
        sa_total = 0
        sm_total = 0
        if j_line:
            if session_slot_number not in u_dict['trend']['slot']:
                u_dict['trend']['slot'][session_slot_number] = {}
            if session_dp_number not in u_dict['trend']['slot'][session_slot_number]:
                u_dict['trend']['slot'][session_slot_number][session_dp_number] = {}
            u_dict['trend']['slot'][session_slot_number][session_dp_number]['c'] = int(j_line['cps_installed'])
            u_dict['trend']['slot'][session_slot_number][session_dp_number]['p'] = int(j_line['throughput_pps'])
            u_dict['trend']['slot'][session_slot_number][session_dp_number]['u'] = int(j_line['session_util'])
            u_dict['trend']['slot'][session_slot_number][session_dp_number]['sa'] = int(j_line['session_active'])
            u_dict['trend']['slot'][session_slot_number][session_dp_number]['su'] = int(
                j_line['session_ssl_proxy_util'])
            u_dict['trend']['slot'][session_slot_number][session_dp_number]['sm'] = int(j_line['session_max'])
            sm_total = sm_total + int(j_line['session_max'])
            t_total = t_total + int(j_line['throughput_kbps'])
            c_total = c_total + int(j_line['cps_installed'])
            sa_total = sa_total + int(j_line['session_active'])
        u_dict['trend']['t'] = t_total
        u_dict['trend']['c'] = c_total
        u_dict['trend']['s'] = sa_total
        gsu = sa_total / sm_total
        u_dict['trend']['gsu'] = gsu
    return u_dict


##########################################################
#
#       Packet Buffer / Descriptor Info
#
##########################################################


def packetBnD(fw, api_key, u_dict):
    xpath = "<show><system><state><filter>sw.mprelay.s*.dp*.packetbuffers</filter>" \
            "</state></system></show>&key="
    prefix = "https://{}/api/?type=op&cmd=".format(fw.mgmt_ip)

    # Slot/DP match criteria
    match_pkt_slot = re.compile('(?<=relay\.)(s.*)(?=\.dp)')
    match_pkt_dp = re.compile('(?<=\.)(dp.*)(?=\.packet)')

    # Match criteria for JSON formatting
    match_begin = re.compile(': (?=[a-zA-Z])')
    match_end = re.compile('(?<=[a-z]),')
    match_end_2 = re.compile(' (?=})')

    pkt_req = requests.get(prefix + xpath + api_key, verify=False)
    pkt_xml = et.fromstring(pkt_req.content)
    pkt_text = pkt_xml.find('./result').text
    pkt_text = pkt_text.split('\n')

    for line in pkt_text:
        if line == "":
            break
        label = line[:line.find('{')]
        pkt_slot_number = re.search(match_pkt_slot, label).group(0)
        pkt_dp_number = re.search(match_pkt_dp, label).group(0)
        line = line[line.find('{'):]
        line = line.replace('\'', '"')
        line = line.replace(', }', ' }')
        line = re.sub(match_begin, ':"', line)
        line = re.sub(match_end, '", ', line)
        # line = re.sub(match_end_2, '"', line)
        j_line = json.loads(line)
        if j_line:
            if pkt_slot_number not in u_dict['trend']['slot']:
                u_dict['trend']['slot'][pkt_slot_number] = {}
            if pkt_dp_number not in u_dict['trend']['slot'][pkt_slot_number]:
                u_dict['trend']['slot'][pkt_slot_number][pkt_dp_number] = {}
        u_dict['trend']['slot'][pkt_slot_number][pkt_dp_number]['pb'] = int(j_line['hw-buf']['used'])
        u_dict['trend']['slot'][pkt_slot_number][pkt_dp_number]['pd'] = int(j_line['pkt-descr']['used'])
    return u_dict


##########################################################
#
#       Interface Stats & Rate
#
##########################################################


def intStats(fw, api_key, u_dict):
    rate_xpath = "<show><system><state><filter>sys.s*.p*.rate</filter></state></sy" \
                 "stem></show>&key="
    stats_xpath = "<show><system><state><filter>net.s*.eth*.stats</filter></state>" \
                  "</system></show>&key="
    prefix = "https://{}/api/?type=op&cmd=".format(fw.mgmt_ip)

    match_begin = re.compile(': (?=[0-9a-fA-Z])')
    match_end = re.compile(',(?= ")')
    match_end_2 = re.compile(' (?=})')

    # Slot/int match criteria for rate node
    match_rate_slot = re.compile('(?<=sys\.s)(.*)(?=\.p)')
    match_rate_interface = re.compile('(?<=\.p)(.*)(?=\.rate)')

    # Slot/int match criteria for stats node
    match_stats_slot = re.compile('(?<=net\.s)(.*)(?=\.eth)')
    match_stats_interface = re.compile('(?<=\.eth)(.*)(?=\.stats)')

    if fw.os_ver[:3] == "8.0":
        rate_req = requests.get(prefix + rate_xpath + api_key, verify=False)
        rate_xml = et.fromstring(rate_req.content)
        rate_text = rate_xml.find('./result').text
        if rate_text is None:
            print "No rate data"
        else:
            rate_text = rate_text.split('\n')

        for line in rate_text:
            if line == "":
                break
            label = line[:line.find('{')]
            rate_slot_number = re.search(match_rate_slot, label).group(0)
            rate_int_number = re.search(match_rate_interface, label).group(0)
            int_label = "{}/{}".format(str(rate_slot_number), str(rate_int_number))
            line = line[line.find('{'):]
            line = line.replace('\'', '"')
            line = line.replace(', }', ' }')
            line = re.sub(match_begin, ':"', line)
            line = re.sub(match_end, '",', line)
            line = re.sub(match_end_2, '"', line)
            j_line = json.loads(line)
            if int_label not in u_dict['trend']['i']:
                u_dict['trend']['i'][int_label] = {}
            u_dict['trend']['i'][int_label]['t'] = int(j_line['tx-bytes'])
            u_dict['trend']['i'][int_label]['r'] = int(j_line['rx-bytes'])
            u_dict['trend']['i'][int_label]['tb'] = int(j_line['tx-broadcast'])
            u_dict['trend']['i'][int_label]['rb'] = int(j_line['rx-broadcast'])
            u_dict['trend']['i'][int_label]['tu'] = int(j_line['tx-unicast'])
            u_dict['trend']['i'][int_label]['ru'] = int(j_line['rx-unicast'])
            u_dict['trend']['i'][int_label]['tm'] = int(j_line['tx-multicast'])
            u_dict['trend']['i'][int_label]['rm'] = int(j_line['rx-multicast'])
            r_total = int(j_line['rx-broadcast']) + int(j_line['rx-unicast']) + int(j_line['rx-multicast'])
            t_total = int(j_line['tx-broadcast']) + int(j_line['tx-unicast']) + int(j_line['tx-multicast'])
            u_dict['trend']['i'][int_label]['rp'] = r_total
            u_dict['trend']['i'][int_label]['tp'] = t_total
    return u_dict


##########################################################
#
#       Interface Errors
#
##########################################################


# def intErrors(fw, api_key, u_dict):
#     err_xpath = "<show><system><state><filter>sys.s*.p*.detail</filter></state></sy" \
#                 "stem></show>&key="
#     prefix = "https://{}/api/?type=op&cmd=".format(fw.mgmt_ip)
#
#     match_begin = re.compile(': (?=[0-9a-fA-Z])')
#     match_end = re.compile(',(?= ")')
#     match_end_2 = re.compile(' (?=})')
#     num_quote = re.compile('(?=, )')
#
#     match_err_slot = re.compile('(?<=sys\.s)(.*)(?=\.p)')
#     match_err_interface = re.compile('(?<=\.p)(.*)(?=\.detail)')
#
#     err_req = requests.get(prefix + err_xpath + api_key, verify=False)
#     err_req_xml = et.fromstring(err_req.content)
#     err_text = err_req_xml.find('./result').text
#
#     if err_text is None:
#         print "No error data"
#     else:
#         err_text = err_text.split('\n')
#
#     for line in err_text:
#         if line == "":
#             break
#         label = line[:line.find('{')]
#         err_slot_number = re.search(match_err_slot, label).group(0)
#         err_int_number = re.search(match_err_interface, label).group(0)
#         int_label = "{}/{}".format(str(err_slot_number), str(err_int_number))
#         line = line[line.find('{'):]
#         if len(line) == 3:
#             pass
#         else:
#             line = line[line.find('{'):]
#             line = line.replace('\'', '"')
#             line = line.replace(', }', ' }')
#             line = re.sub(match_begin, ': "', line)
#             line = re.sub(num_quote, '"', line)
#             line = re.sub(match_end_2, '"', line)
#             j_line = json.loads(line)
#             if "mac_transmit_err" in j_line:
#                 if int_label not in u_dict['trend']['i']:
#                     u_dict['trend']['i'][int_label] = {}
#                 te_int = int(j_line['mac_transmit_err'])
#                 u_dict['trend']['i'][int_label]['te'] = te_int
#             if "mac_rcv_err" in j_line:
#                 if int_label not in u_dict['trend']['i']:
#                     u_dict['trend']['i'][int_label] = {}
#                 re_int = int(j_line['mac_rcv_err'])
#                 u_dict['trend']['i'][int_label]['re'] = re_int
#             if "rcv_fifo_overrun" in j_line:
#                 if int_label not in u_dict['trend']['i']:
#                     u_dict['trend']['i'][int_label] = {}
#                 rd_int = int((j_line['rcv_fifo_overrun']), 16)
#                 u_dict['trend']['i'][int_label]['rd'] = rd_int
#     return u_dict


def intErrors(fw, api_key, u_dict):
    ierr_params = {'type' : 'op',
                   'cmd' : '<show><counter><interface>all</interface></counter></show>',
                   'key' : api_key}
    ierr_req = requests.get("https://{}/api/?".format(fw.mgmt_ip), params=ierr_params, verify=False)
    ierr_xml = et.fromstring(ierr_req.content)
    int_list = ierr_xml.findall('./result/ifnet/ifnet/*')
    for entry in int_list:
        int_label = entry.find('name').text
        int_label = int_label.strip('ethernet')
        ierrors = entry.find('ierrors').text
        idrops = entry.find('idrops').text
        if int_label not in u_dict['trend']['i']:
            u_dict['trend']['i'][int_label] = {}
        u_dict['trend']['i'][int_label]['re'] = ierrors
        u_dict['trend']['i'][int_label]['rd'] = idrops
    return u_dict





##########################################################
#
#       Interface State
#
##########################################################


def intState(fw, api_key, u_dict):
    state_xpath = "<show><system><state><filter>sw.dev.runtime.ifmon.port-states</f" \
                  "ilter></state></system></show>&key="
    prefix = "https://{}/api/?type=op&cmd=".format(fw.mgmt_ip)

    match_begin = re.compile(': (?=[0-9a-fA-Z])')
    match_end = re.compile(',(?= ")')
    #match_end_2 = re.compile(' (?=[0-9a-zA-Z])')
    match_brace = re.compile('(?<=[A-Za-z0-9]) }')


    state_req = requests.get(prefix + state_xpath + api_key, verify=False)
    state_xml = et.fromstring(state_req.content)
    state_text = state_xml.find('./result').text
    if state_text is None:
        print "No port state data"
    else:
        state_text = state_text.split('\n')


    line = state_text[0]
    line = line[line.find('{'):]
    line = line.replace('\'', '"')
    line = line.replace(', }', ' }')
    line = re.sub(match_begin, ':"', line)
    line = re.sub(match_end, '",', line)
    # line = re.sub(match_end_2, '"', line)
    line = re.sub(match_brace, '" }', line)
    line = line.replace('}"', '}')
    j_line = json.loads(line)


    #TODO: Release note the interface count issue.
    for key in j_line:
        if j_line[key]['link'] == "Up":
            p_status = 1
        else:
            p_status = 0
        u_dict['status']['ports'][key] = {'pu' : p_status}
    return u_dict



##########################################################
#
#       Log Rate
#
##########################################################


def logRate(fw, api_key, u_dict):
    xpath = "<show><system><state><filter>sw.mgmt.runtime.lograte</filter></state>" \
            "</system></show>&key="

    xpath_alt = "<show><system><state><filter>sw.logrcvr.runtime.write-lograte</fi" \
                "lter></state></system></show>&key="
    prefix = "https://{}/api/?type=op&cmd=".format(fw.mgmt_ip)
    # Check both version and platform to see if this is a physical device vs. VM
    skiplist = ["vm", "200", "220", "500", "800", "3000", "5000"]

    if (fw.os_ver[:3] == "8.0") and (fw.family not in skiplist):
        lograte_req = requests.get(prefix + xpath + api_key, verify=False)
        lograte_xml = et.fromstring(lograte_req.content)
        lograte_text = lograte_xml.find('./result').text
        lograte_text = lograte_text[lograte_text.find(':'):]
        lograte_text = lograte_text[2:]
        lograte_int = int(lograte_text, 16)
        u_dict['trend']['l'] = lograte_int
    else:
        lograte_req = requests.get(prefix + xpath_alt + api_key, verify=False)
        lograte_xml = et.fromstring(lograte_req.content)
        lograte_text = lograte_xml.find('./result').text
        try:
            lograte_text = lograte_text[lograte_text.find(':'):]
        except AttributeError as e:
            logger.error("Attribute error getting log rate for {}, S/N {}.".format(fw.h_name, fw.ser_num))
            logger.debug("URL sent:\n{}{} response:\n{}".format(lograte_req.url, fw.h_name, lograte_req.content))
        lograte_text = lograte_text[2:]
        u_dict['trend']['l'] = int(lograte_text)
    return u_dict


##########################################################
#
#       Environmentals - Fans
#
##########################################################

# TODO: Extract the model check to main function

def envFans(fw, api_key, u_dict):

    xpath = "<show><system><state><filter>env.s*.fan.*</filter></state></syste" \
            "m></show>&key="
    prefix = "https://{}/api/?type=op&cmd=".format(fw.mgmt_ip)

    match_end = re.compile(',(?= ")')
    match_begin = re.compile(': (?=[0-9a-fA-Z])')
    match_fan_slot = re.compile('(?<=env\.s)(.*)(?=\.fan)')
    match_fan_number = re.compile('(?<=fan\.)(.*)(?=:)')

    rate_req = requests.get(prefix + xpath + api_key, verify=False)
    rate_xml = et.fromstring(rate_req.content)
    rate_text = rate_xml.find('./result').text
    try:
        rate_text = rate_text.split('\n')
    except AttributeError as e:
        logger.error("Error getting fan data for {}, S/N {}. Response is:\n{}"
                     .format(fw.h_name, fw.ser_num, rate_req.content))

    for resp_string in rate_text:
        if resp_string == "":
            break
        label = resp_string[:resp_string.find('{')]
        fan_slot_number = re.search(match_fan_slot, label).group(0)
        fan_number = re.search(match_fan_number, label).group(0)
        fan_number = fan_number.replace('.', '/')
        resp_string = resp_string[resp_string.find('{'):]
        resp_string = resp_string.replace('\'', '"')
        resp_string = resp_string.replace(', }', ' }')
        resp_string = resp_string.replace(', ]', ' ]')
        resp_string = re.sub(match_begin, ': "', resp_string)
        resp_string = re.sub(match_end, '", ', resp_string)
        if fw.family == "500":
            match_end_2 = re.compile(' (?=})')
            resp_string = re.sub(match_end_2, '"', resp_string)
        j_line = ast.literal_eval(resp_string)
        f_string = "fan{}/{}".format(str(fan_slot_number), str(fan_number))
        if f_string not in u_dict['status']['environmentals']['fans']:
            u_dict['status']['environmentals']['fans'][f_string] = {}
        if j_line['alarm'] == 'False':
            u_dict['status']['environmentals']['fans'][f_string]['alrm'] = 0
        else:
            u_dict['status']['environmentals']['fans'][f_string]['alrm'] = 1
        if fw.family == "500":
            u_dict['status']['environmentals']['fans'][f_string]['rpm'] = 0
        else:
            u_dict['status']['environmentals']['fans'][f_string]['rpm'] = int(j_line['avg'])
        u_dict['status']['environmentals']['fans'][f_string]['de'] = str(j_line['desc'])
    return u_dict


##########################################################
#
#       Environmentals - Power
#
##########################################################


def envPower(fw, api_key, u_dict):
    ps_xpath = "<show><system><state><filter>env.s*.power-supply.*</filter><" \
               "/state></system></show>&key="
    prefix = "https://{}/api/?type=op&cmd=".format(fw.mgmt_ip)
    match_begin = re.compile(': (?=[0-9a-fA-Z])')
    match_end = re.compile(',(?= ")')
    match_brace = re.compile('(?= })')

    match_power_slot = re.compile('(?<=env\.s)(.*)(?=\.power-supply)')
    match_power_number = re.compile('(?<=supply\.)(.*)(?=:)')

    ps_req = requests.get(prefix + ps_xpath + api_key, verify=False)
    ps_text = ps_req.content
    ps_text = ''.join([i if ord(i) < 128 else '0' for i in ps_text])
    ps_xml = et.fromstring(ps_text)
    ps_text = ps_xml.find('./result').text
    if ps_text is None:
        print "No power supply data"
    else:
        ps_text = ps_text.split('\n')

    for line in ps_text:
        if line == "":
            break
        label = line[:line.find('{')]
        power_slot = re.search(match_power_slot, label).group(0)
        power_number = re.search(match_power_number, label).group(0)
        p_string = "power{}/{}".format(str(power_slot), str(power_number))
        line = line[line.find('{'):]
        line = line.replace('\'', '"')
        line = line.replace(', }', ' }')
        line = re.sub(match_begin, ':"', line)
        line = re.sub(match_end, '",', line)
        line = re.sub(match_brace, '"', line)
        line = line.replace(': ",', ': "",')
        line = line.replace(': " ', ': "" ')
        j_line = json.loads(line)
        if p_string not in u_dict['status']['environmentals']['power']:
            u_dict['status']['environmentals']['power'][p_string] = {}
        if str(j_line['alarm']) == "False":
            u_dict['status']['environmentals']['power'][p_string]['alrm'] = 0
        else:
            u_dict['status']['environmentals']['power'][p_string]['alrm'] = 1
        if str(j_line['present']) == "False":
            u_dict['status']['environmentals']['power'][p_string]['ins'] = 0
        else:
            u_dict['status']['environmentals']['power'][p_string]['ins'] = 1
        u_dict['status']['environmentals']['power'][p_string]['de'] = str(j_line['desc'])
    return u_dict

##########################################################
#
#       Environmentals - Thermal
#
##########################################################


def envThermal(fw, api_key, u_dict):
    xpath = "<show><system><state><filter>env.s*.thermal.*</filter></state></syste" \
            "m></show>&key="
    prefix = "https://{}/api/?type=op&cmd=".format(fw.mgmt_ip)

    # Slot/Sensor match criteria
    match_therm_slot = re.compile('(?<=env\.s)(.*)(?=\.therm)')
    match_therm_sensor = re.compile(('(?<=mal\.)(.*)(?=:)'))

    # Match criteria for JSON formatting
    match_begin = re.compile(': (?=[A-Z0-9\-\[])')
    match_end = re.compile(',(?= ")')
    match_end_2 = re.compile(' (?=})')
    # match_wonk = re.compile('[0-9]\](?=,)')

    therm_req = requests.get(prefix + xpath + api_key, verify=False)

    therm_xml = et.fromstring(therm_req.content)
    therm_text = therm_xml.find('./result').text
    if therm_text == None:
        print "No thermal data"
    else:
        therm_text = therm_text.split('\n')
    if fw.family == ("7000" or "800" or "220" or "500" or "3000" or "5000"):
        for line in therm_text:
            if line == "":
                break
            label = line[:line.find('{')]
            therm_slot_number = re.search(match_therm_slot, label).group(0)
            therm_sensor_number = re.search(match_therm_sensor, label).group(0)
            line = line[line.find('{'):]
            line = line.replace('\'', '"')
            line = line.replace(', }', ' }')
            line = line.replace(', ]', ' ]')
            line = re.sub(match_begin, ': "', line)
            line = re.sub(match_end, '", ', line)
            line = line.replace('"[', '[')
            j_line = ast.literal_eval(line)
            t_string = "thermal{}/{}".format(str(therm_slot_number), str(therm_sensor_number))
            if t_string not in u_dict['status']['environmentals']['thermal']:
                u_dict['status']['environmentals']['thermal'][t_string] = {}
            if str(j_line['alarm']) == 'False':
                u_dict['status']['environmentals']['thermal'][t_string]['alrm'] = 0
            else:
                u_dict['status']['environmentals']['thermal'][t_string]['alrm'] = 1
            u_dict['status']['environmentals']['thermal'][t_string]['de'] = str(j_line['desc'])
            u_dict['status']['environmentals']['thermal'][t_string]['tm'] = float(j_line['avg'])

    else:
        for line in therm_text:
            if line == "":
                break
            label = line[:line.find('{')]
            therm_slot_number = re.search(match_therm_slot, label).group(0)
            therm_sensor_number = re.search(match_therm_sensor, label).group(0)
            line = line[line.find('{'):]
            line = line.replace('\'', '"')
            line = line.replace(', }', ' }')
            line = line.replace(', ]', ' ]')
            line = re.sub(match_begin, ': "', line)
            line = re.sub(match_end, '", ', line)
            # line = line.replace(']"', ']')
            line = re.sub(match_end_2, '" ', line)
            # line = re.sub(match_wonk, '"', line)
            j_line = ast.literal_eval(line)
            t_string = "thermal{}/{}".format(str(therm_slot_number), str(therm_sensor_number))
            if t_string not in u_dict['status']['environmentals']['thermal']:
                u_dict['status']['environmentals']['thermal'][t_string] = {}
            u_dict['status']['environmentals']['thermal'][t_string]['alrm'] = str(j_line['alarm'])
            u_dict['status']['environmentals']['thermal'][t_string]['de'] = str(j_line['desc'])
            u_dict['status']['environmentals']['thermal'][t_string]['tm'] = str(j_line['avg'])
    return u_dict

##########################################################
#
#       Environmentals - Disk Partitions
#
##########################################################


def envPartitions(fw, api_key, u_dict):
    partition_xpath = "<show><system><state><filter>resource.s*.mp.partition</filte" \
                      "r></state></system></show>&key="
    prefix = "https://{}/api/?type=op&cmd=".format(fw.mgmt_ip)
    match_begin = re.compile(': (?=[0-9a-fA-Z])')
    match_end = re.compile(',(?= ")')
    match_end_2 = re.compile(' (?=})')
    match_brace = re.compile('(?<=[A-Za-z0-9]) }')

    part_req = requests.get(prefix + partition_xpath + api_key, verify=False)
    part_xml = et.fromstring(part_req.content)
    part_text = part_xml.find('./result').text

    line = part_text[part_text.find('{'):]
    line = line.replace('\'', '"')
    line = line.replace(', }', ' }')
    line = re.sub(match_begin, ':"', line)
    line = re.sub(match_end, '",', line)
    line = re.sub(match_brace, '" }', line)
    line = line.replace('}"', '}')
    j_line = json.loads(line)
    for key in j_line:
        if key not in u_dict['status']['environmentals']['mounts']:
            u_dict['status']['environmentals']['mounts'][key] = {}
        size = int(j_line[key]['size'], 16)
        used = int(j_line[key]['used'], 16)
        avail = size - used
        pct_used = round((float(used) / float(size)) * 100, 0)
        u_dict['status']['environmentals']['mounts'][key]['al'] = size
        u_dict['status']['environmentals']['mounts'][key]['us'] = used
        u_dict['status']['environmentals']['mounts'][key]['a'] = avail
        u_dict['status']['environmentals']['mounts'][key]['put'] = pct_used
    return u_dict


##########################################################
#
#       Environmentals - Raid Status
#
##########################################################


def envRaid(fw, api_key, u_dict):
    raid_xpath = "<show><system><state><filter>sys.raid.s*.ld*.drives</filter></sta" \
                 "te></system></show>&key="
    prefix = "https://{}/api/?type=op&cmd=".format(fw.mgmt_ip)
    match_begin = re.compile(': (?=[0-9a-fA-Z])')
    match_end = re.compile(',(?= ")')
    match_end_2 = re.compile(' (?=})')

    match_raid_slot = re.compile('(?<=raid\.s)(.*)(?=\.ld)')
    match_raid_ld = re.compile('(?<=\.ld)(.*)(?=\.drives)')

    raid_req = requests.get(prefix + raid_xpath + api_key, verify=False)
    raid_xml = et.fromstring(raid_req.content)
    raid_text = raid_xml.find('./result').text

    if raid_text is None:
        print "No RAID data"
    else:
        raid_text = raid_text.split('\n')

    for line in raid_text:
        if line == "":
            break
        label = line[:line.find('{')]
        raid_slot_number = re.search(match_raid_slot, label).group(0)
        raid_slot_number = "s{}".format(raid_slot_number)
        raid_ld_number = re.search(match_raid_ld, label).group(0)
        raid_ld_number = "l{}".format(raid_ld_number)
        line = line[line.find('{'):]
        line = line.replace('\'', '"')
        line = line.replace(', }', ' }')
        line = re.sub(match_begin, ':"', line)
        line = re.sub(match_end, '",', line)
        line = re.sub(match_end_2, '"', line)
        line = line.replace('}"', '} ')
        j_line = json.loads(line)
        if raid_slot_number not in u_dict['status']['environmentals']['disks']:
            u_dict['status']['environmentals']['disks'][raid_slot_number] = {}
        if raid_ld_number not in u_dict['status']['environmentals']['disks'][raid_slot_number]:
            u_dict['status']['environmentals']['disks'][raid_slot_number][raid_ld_number] = {}
        for n in range(0, 2):
            u_dict['status']['environmentals']['disks'][raid_slot_number][raid_ld_number][n] = {}
            u_dict['status']['environmentals']['disks'][raid_slot_number][raid_ld_number][n]['n'] = str(
                j_line[str(n)]['name'])
            u_dict['status']['environmentals']['disks'][raid_slot_number][raid_ld_number][n]['z'] = str(
                j_line[str(n)]['size'])
            if j_line[str(n)]['status'] == 'active sync':
                u_dict['status']['environmentals']['disks'][raid_slot_number][raid_ld_number][n]['s'] = 1
            else:
                u_dict['status']['environmentals']['disks'][raid_slot_number][raid_ld_number][n]['s'] = 0
    return u_dict


##########################################################
#
#       Log Forwarding
#
##########################################################


def logFwd(fw, api_key, u_dict):

    autotag = ['autotag', {'avg': 'sw.logrcvr.autotag_avg_send_rate', 'sent': 'sw.logrcvr.autotag_sent_count',
                           'drop': 'sw.logrcvr.autotag_drop_count'}]

    http = ['http', {'avg': 'sw.logrcvr.http_avg_send_rate', 'sent': 'sw.logrcvr.http_sent_count',
                     'drop': 'sw.logrcvr.http_drop_count'}]

    raw = ['raw', {'avg': 'sw.logrcvr.raw_avg_send_rate', 'sent': 'sw.logrcvr.raw_sent_count',
                   'drop': 'sw.logrcvr.raw_drop_count'}]

    email = ['email', {'avg': 'sw.logrcvr.email_avg_send_rate', 'sent': 'sw.logrcvr.email_sent_count',
                       'drop': 'sw.logrcvr.email_drop_count'}]

    snmp = ['snmp', {'avg': 'sw.logrcvr.snmp_avg_send_rate', 'sent': 'sw.logrcvr.snmp_sent_count',
                     'drop': 'sw.logrcvr.snmp_drop_count'}]

    syslog = ['syslog', {'avg': 'sw.logrcvr.syslog_avg_send_rate', 'sent': 'sw.logrcvr.syslog_sent_count',
                         'drop': 'sw.logrcvr.syslog_drop_count'}]

    node_list = [autotag, http, raw, email, snmp, syslog]
    prefix = "https://{}/api/?type=op&cmd=".format(fw.mgmt_ip)
    for node in node_list:
        for m_key in node[1]:
            xpath = "<show><system><state><filter>{}</filter></state></system></show>&key=".format(node[1][m_key])
            node_req = requests.get(prefix + xpath + api_key, verify=False)
            node_xml = et.fromstring(node_req.content)
            node_text = node_xml.find('./result').text
            node_text = node_text[node_text.find(': ') + 2:]
            u_dict['status']['logging-external']['external'][node[0]][m_key] = int(node_text)
    return u_dict


##########################################################
#
#       Send to Panorama
#
##########################################################


def sendData(fw, pano_ip, key, u_dict):
    prefix = "http://{}/api/?".format(pano_ip)
    headerlist = {'Content-Type' : 'application/x-www-form-urlencoded'}
    update_str = json.dumps(u_dict)
    cmd = "type=op&key={}&cmd=<monitoring><external-input><device>{}</device><d" \
          "ata><![CDATA[{}]]></data></external-input></monitoring>".format(key, fw.ser_num, update_str)
    update_req = requests.post(prefix, headers=headerlist, data=cmd, verify=False)
    logger.debug("Update sent for device {}, S/N {}. URL:{}".format(fw.h_name, fw.ser_num, update_req.url))
    try:
        update_resp = et.fromstring(update_req.content)
    except Exception as e:
        logger.error("Could not convert response to XML object. Device {}, S/N {} "
                     "response:\n{}".format(fw.h_name, fw.ser_num, update_req.content))
        return
    logger.debug("Response for {}, S/N {}:\n{}".format(fw.h_name, fw.ser_num, update_req.content))
    logger.debug("Status for {}, S/N {}: {}".format(fw.h_name, fw.ser_num, update_resp.attrib['status']))
    return update_resp.attrib['status']























