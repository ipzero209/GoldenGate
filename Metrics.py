#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
import json
import panFW
import ast
import re

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

##########################################################
#
#       DP CPU
#
##########################################################


def dpCPU(fw, api_key, u_dict):
    xpath = "<show><system><state><filter>sys.monitor.s*.dp*.exports</filter></sta" \
            "te></system></show>"
    prefix = "https://{}/api/?".format(fw.mgmt_ip)
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
            "</state></system></show>"
    prefix = "https://{}/api?".format(fw.mgmt_ip)

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
            t_total = t_total + int(j_line['throughput_kbps'])
            c_total = c_total + int(j_line['cps_installed'])
            sa_total = sa_total + int(j_line['session_active'])
        u_dict['trend']['t'] = t_total
        u_dict['trend']['c'] = c_total
        u_dict['trend']['s'] = sa_total
    return u_dict


##########################################################
#
#       Packet Buffer / Descriptor Info
#
##########################################################


def packetBnD(fw, u_dict, api_key):
    xpath = "<show><system><state><filter>sw.mprelay.s*.dp*.packetbuffers</filter>" \
            "</state></system></show>"
    prefix = "https://{}/api/?"

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


def intStats(fw, u_dict, api_key):
    rate_xpath = "<show><system><state><filter>sys.s*.p*.rate</filter></state></sy" \
                 "stem></show>"
    stats_xpath = "<show><system><state><filter>net.s*.eth*.stats</filter></state>" \
                  "</system></show>"
    prefix = "https://{}/api/?".format(fw.mgmt_ip)

    match_begin = re.compile(': (?=[0-9a-fA-Z])')
    match_end = re.compile(',(?= ")')
    match_end_2 = re.compile(' (?=})')

    # Slot/int match criteria for rate node
    match_rate_slot = re.compile('(?<=sys\.s)(.*)(?=\.p)')
    match_rate_interface = re.compile('(?<=\.p)(.*)(?=\.rate)')

    # Slot/int match criteria for stats node
    match_stats_slot = re.compile('(?<=net\.s)(.*)(?=\.eth)')
    match_stats_interface = re.compile('(?<=\.eth)(.*)(?=\.stats)')

    if thisFW.os_ver[:3] == "8.0":
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
    return u_dict


##########################################################
#
#       Interface Errors
#
##########################################################


def intErrors(fw, u_dict, api_key):
    err_xpath = "<show><system><state><filter>sys.s*.p*.detail</filter></state></sy" \
                "stem></show>"
    prefix = "https://{}/api/?".format(fw.mgmt_ip)

    match_begin = re.compile(': (?=[0-9a-fA-Z])')
    match_end = re.compile(',(?= ")')
    match_end_2 = re.compile(' (?=})')
    num_quote = re.compile('(?=, )')

    match_err_slot = re.compile('(?<=sys\.s)(.*)(?=\.p)')
    match_err_interface = re.compile('(?<=\.p)(.*)(?=\.detail)')

    err_req = requests.get(prefix + err_xpath + api_key, verify=False)
    err_req_xml = et.fromstring(err_req.content)
    err_text = err_req_xml.find('./result').text

    if err_text is None:
        print "No error data"
    else:
        err_text = err_text.split('\n')

    for line in err_text:
        if line == "":
            break
        label = line[:line.find('{')]
        err_slot_number = re.search(match_err_slot, label).group(0)
        err_int_number = re.search(match_err_interface, label).group(0)
        int_label = "{}/{}".format(str(err_slot_number), str(err_int_number))
        line = line[line.find('{'):]
        if len(line) == 3:
            pass
        else:
            line = line[line.find('{'):]
            line = line.replace('\'', '"')
            line = line.replace(', }', ' }')
            line = re.sub(match_begin, ': "', line)
            line = re.sub(num_quote, '"', line)
            line = re.sub(match_end_2, '"', line)
            j_line = json.loads(line)
            if "mac_transmit_err" in j_line:
                if int_label not in u_dict['trend']['i']:
                    u_dict['trend']['i'][int_label] = {}
                te_int = int(j_line['mac_transmit_err'])
                u_dict['trend']['i'][int_label]['te'] = te_int
            if "mac_rcv_err" in j_line:
                if int_label not in u_dict['trend']['i']:
                    u_dict['trend']['i'][int_label] = {}
                re_int = int(j_line['mac_rcv_err'])
                u_dict['trend']['i'][int_label]['re'] = re_int
            if "rcv_fifo_overrun" in j_line:
                if int_label not in u_dict['trend']['i']:
                    u_dict['trend']['i'][int_label] = {}
                rd_int = int((j_line['rcv_fifo_overrun']), 16)
                u_dict['trend']['i'][int_label]['rd'] = rd_int
    return u_dict


##########################################################
#
#       Interface State
#
##########################################################


def intState(fw, u_dict, api_key):
    state_xpath = "<show><system><state><filter>sw.dev.runtime.ifmon.port-states</f" \
                  "ilter></state></system></show>"
    prefix = "https://{}/api/?".format(fw.mgmt_ip)

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


def logRate(fw, u_dict, api_key):
    xpath = "<show><system><state><filter>sw.mgmt.runtime.lograte</filter></state>" \
            "</system></show>"

    xpath_alt = "<show><system><state><filter>sw.logrcvr.runtime.write-lograte</fi" \
                "lter></state></system></show>"
    prefix = "https://{}/api/?".format(fw.mgmt_ip)
    # Check both version and platform to see if this is a physical device vs. VM
    skiplist = ["vm", "200", "220", "500", "800", "3000", "5000"]

    if (thisFW.os_ver[:3] == "8.0") and (thisFW.family not in skiplist):
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
        lograte_text = lograte_text[lograte_text.find(':'):]
        lograte_text = lograte_text[2:]
        u_dict['trend']['l'] = int(lograte_text)
    return u_dict




















