#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
import json
import re
import panFW
import ast
# -------- Remove below here --------
import sys
# import pudb
# -------- Remove above here --------

from requests.packages.urllib3.exceptions import InsecureRequestWarning

thisFW = panFW.Device('009908000102', '10.3.5.138', '8.0.5', 'vm')



# To suppress certificate warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

api_key = "&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"
prefix = "https://10.3.5.138/api/?type=op&cmd="
pano_prefix =  "https://10.3.4.63/api/?type=op&cmd="


update_dict = {'trend':{}}
update_dict['status'] = {}
update_dict['trend']['slot'] = {}
update_dict['trend']['i'] = {}
# update_dict['trend']['status'] = {}
update_dict['status']['logging-external'] = {}
update_dict['status']['logging-external']['external'] = {'autotag':{}, 'http':{}, 'raw':{}, 'email':{}, 'snmp':{}, 'syslog':{}}
update_dict['status']['ports'] = {}
update_dict['status']['environmentals'] = {}
update_dict['status']['environmentals']['mounts'] = {}

##########################################################
#
#       MP CPU
#
##########################################################

xpath = "<show><system><state><filter>sys.monitor.s*.mp.exports</filter></stat" \
        "e></system></show>"


mp_cpu_req = requests.get(prefix + xpath + api_key, verify=False)
mp_cpu_xml = et.fromstring(mp_cpu_req.content)
mp_cpu_text = mp_cpu_xml.find('./result').text
mp_cpu_text = mp_cpu_text[mp_cpu_text.find('{'):]
mp_cpu_text = mp_cpu_text.replace('\'', '"')
mp_cpu_text = mp_cpu_text.replace(', }', ' }')
mp_cpu_json = json.loads(mp_cpu_text)
update_dict['trend']['m'] = int(mp_cpu_json['cpu']['1minavg'])
#update_string = update_string + "m:{},".format(mp_cpu_json['cpu']['1minavg'])




##########################################################
#
#       MP MEM
#
##########################################################

xpath = "<show><system><state><filter>resource.s*.mp.memory</filter></state></" \
        "system></show>"

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
used_mem_pct = (float(used_mem_int)/float(total_mem_int)) * 100  #TODO: round if you have time
update_dict['trend']['mm'] = used_mem_pct
#update_string = update_string + "mmm:{},".format(used_mem_int)


##########################################################
#
#       DP CPU
#
##########################################################

xpath = "<show><system><state><filter>sys.monitor.s*.dp*.exports</filter></sta" \
        "te></system></show>"



dp_cpu_req = requests.get(prefix + xpath + api_key, verify=False)
dp_cpu_xml = et.fromstring(dp_cpu_req.content)
dp_cpu_text = dp_cpu_xml.find('./result').text
dp_cpu_text = dp_cpu_text.split('\n')


# Slot/DP match criteria
match_dp_slot = re.compile('(?<=monitor\.)(s.*)(?=\.dp)')
match_dp_dp = re.compile('(?<=\.)(dp.*)(?=\.exports)')


for line in dp_cpu_text:
    if line == "":
        break
    label = line[:line.find('{')]
    slot_num = re.search(match_dp_slot, label).group(0)
    dp_num = re.search(match_dp_dp, label).group(0)
    # print slot
    # print dp_num
    line = line[line.find('{'):]
    line = line.replace('\'', '"')
    line = line.replace(', }', ' }')
    j_line = json.loads(line)
    d_cpu_list = []
    if j_line:
        if slot_num not in update_dict['trend']['slot']:
            update_dict['trend']['slot'][slot_num] = {}
        if dp_num not in update_dict['trend']['slot'][slot_num]:
            update_dict['trend']['slot'][slot_num][dp_num] = {}
        update_dict['trend']['slot'][slot_num][dp_num]['d'] = int(j_line['cpu']['1minavg'])
        d_cpu_list.append(int(j_line['cpu']['1minavg']))
dcpu_avg = float(sum(d_cpu_list))/float(len(d_cpu_list))
update_dict['trend']['d'] = dcpu_avg




##########################################################
#
#       Session Info
#
##########################################################


xpath = "<show><system><state><filter>sw.mprelay.s*.dp*.stats.session</filter>" \
        "</state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6" \
        "TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"


# Slot/DP match criteria
match_session_slot = re.compile('(?<=mprelay\.)(s.*)(?=\.dp)')
match_session_dp = re.compile('(?<=\.)(dp.*)(?=\.stats)')


session_req = requests.get(prefix + xpath, verify=False)
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
        if session_slot_number not in update_dict['trend']['slot']:
            update_dict['trend']['slot'][session_slot_number] = {}
        if session_dp_number not in update_dict['trend']['slot'][session_slot_number]:
            update_dict['trend']['slot'][session_slot_number][session_dp_number] = {}
        update_dict['trend']['slot'][session_slot_number][session_dp_number]['c'] = int(j_line['cps_installed'])
        update_dict['trend']['slot'][session_slot_number][session_dp_number]['p'] = int(j_line['throughput_pps'])
        update_dict['trend']['slot'][session_slot_number][session_dp_number]['u'] = int(j_line['session_util'])
        update_dict['trend']['slot'][session_slot_number][session_dp_number]['sa'] = int(j_line['session_active'])
        update_dict['trend']['slot'][session_slot_number][session_dp_number]['su'] = int(j_line['session_ssl_proxy_util'])
        update_dict['trend']['slot'][session_slot_number][session_dp_number]['sm'] = int(j_line['session_max'])
        t_total = t_total + int(j_line['throughput_kbps'])
        c_total = c_total + int(j_line['cps_installed'])
        sa_total = sa_total + int(j_line['session_active'])
    update_dict['trend']['t'] = t_total
    update_dict['trend']['c'] = c_total
    update_dict['trend']['s'] = sa_total



##########################################################
#
#       Packet Buffer / Descriptor Info
#
##########################################################


xpath = "<show><system><state><filter>sw.mprelay.s*.dp*.packetbuffers</filter>" \
        "</state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6" \
        "TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"


# Slot/DP match criteria
match_pkt_slot = re.compile('(?<=relay\.)(s.*)(?=\.dp)')
match_pkt_dp = re.compile('(?<=\.)(dp.*)(?=\.packet)')

# Match criteria for JSON formatting
match_begin = re.compile(': (?=[a-zA-Z])')
match_end = re.compile('(?<=[a-z]),')
match_end_2 = re.compile(' (?=})')


pkt_req = requests.get(prefix + xpath, verify=False)
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
        if pkt_slot_number not in update_dict['trend']['slot']:
            update_dict['trend']['slot'][pkt_slot_number] = {}
        if pkt_dp_number not in update_dict['trend']['slot'][pkt_slot_number]:
            update_dict['trend']['slot'][pkt_slot_number][pkt_dp_number] = {}
    update_dict['trend']['slot'][pkt_slot_number][pkt_dp_number]['pb'] = int(j_line['hw-buf']['used'])
    update_dict['trend']['slot'][pkt_slot_number][pkt_dp_number]['pd'] = int(j_line['pkt-descr']['used'])




##########################################################
#
#       Interface Stats & Rate
#
##########################################################


# NOTE: Rate is only supported on 8.0 and later.

rate_xpath = "<show><system><state><filter>sys.s*.p*.rate</filter></state></sy" \
             "stem></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXc" \
             "wM3JHUGVhRlNiY0dCR0srNERUQT09"
stats_xpath = "<show><system><state><filter>net.s*.eth*.stats</filter></state>" \
              "</system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TG" \
              "M9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

err_xpath = "<show><system><state><filter>sys.s*.p*.detail</filter></state></sy" \
            "stem></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM" \
            "3JHUGVhRlNiY0dCR0srNERUQT09"



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
    rate_req = requests.get(prefix + rate_xpath, verify=False)
    rate_xml = et.fromstring(rate_req.content)
    rate_text = rate_xml.find('./result').text
    if rate_text is None:
        print "No rate data"
    else:
        rate_text = rate_text.split('\n')

    # NOTE: Only for 8.0 devices
    # TODO: Check OS version

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
        if int_label not in update_dict['trend']['i']:
            update_dict['trend']['i'][int_label] = {}
        update_dict['trend']['i'][int_label]['t'] = int(j_line['tx-bytes'])
        update_dict['trend']['i'][int_label]['r'] = int(j_line['rx-bytes'])
        update_dict['trend']['i'][int_label]['tb'] = int(j_line['tx-broadcast'])
        update_dict['trend']['i'][int_label]['rb'] = int(j_line['rx-broadcast'])
        update_dict['trend']['i'][int_label]['tu'] = int(j_line['tx-unicast'])
        update_dict['trend']['i'][int_label]['ru'] = int(j_line['rx-unicast'])
        update_dict['trend']['i'][int_label]['tm'] = int(j_line['tx-multicast'])
        update_dict['trend']['i'][int_label]['rm'] = int(j_line['rx-multicast'])





#TODO: Remove stats section

# stats_req = requests.get(prefix + stats_xpath, verify=False)
# stats_xml = et.fromstring(stats_req.content)
# stats_text = stats_xml.find('./result').text
# if stats_text == None:
#     print "No status info"
# stats_text = stats_text.split('\n')
#
#
# for line in stats_text:
#     if line == "":
#         break
#     label = line[:line.find('{')]
#     stats_slot_number = re.search(match_stats_slot, label).group(0)
#     stats_int_number = re.search(match_stats_interface, label).group(0)
#     int_label = "{}/{}".format(str(stats_slot_number), str(stats_int_number))
#     line = line[line.find('{'):]
#     line = line.replace('\'', '"')
#     line = line.replace(', }', ' }')
#     j_line = json.loads(line)
#     if int_label not in update_dict['trend']['i']:
#         update_dict['trend']['i'][int_label] = {}
#     update_dict['trend']['i'][int_label]['te'] = int(j_line['tx-errs'])
#     update_dict['trend']['i'][int_label]['re'] = int(j_line['rx-errs'])





##########################################################
#
#       Interface Errors
#
##########################################################


match_begin = re.compile(': (?=[0-9a-fA-Z])')
match_end = re.compile(',(?= ")')
match_end_2 = re.compile(' (?=})')
num_quote = re.compile('(?=, )')

match_err_slot = re.compile('(?<=sys\.s)(.*)(?=\.p)')
match_err_interface = re.compile('(?<=\.p)(.*)(?=\.detail)')




err_req = requests.get(prefix + err_xpath, verify=False)
err_req_xml = et.fromstring(err_req.content)
err_text = err_req_xml.find('./result').text

if err_text is None:
    print "No error data"
else: err_text = err_text.split('\n')

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
            if int_label not in update_dict['trend']['i']:
                update_dict['trend']['i'][int_label] = {}
            te_int = int(j_line['mac_transmit_err'])
            update_dict['trend']['i'][int_label]['te'] = te_int
        if "mac_rcv_err" in j_line:
            if int_label not in update_dict['trend']['i']:
                update_dict['trend']['i'][int_label] = {}
            re_int = int(j_line['mac_rcv_err'])
            update_dict['trend']['i'][int_label]['re'] = re_int
        if "rcv_fifo_overrun" in j_line:
            if int_label not in update_dict['trend']['i']:
                update_dict['trend']['i'][int_label] = {}
            rd_int = int(j_line['rcv_fifo_overrun'])
            update_dict['trend']['i'][int_label]['rd'] = rd_int


##########################################################
#
#       Interface State
#
##########################################################





state_xpath = "<show><system><state><filter>sw.dev.runtime.ifmon.port-states</f" \
              "ilter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpne" \
              "mh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"




match_begin = re.compile(': (?=[0-9a-fA-Z])')
match_end = re.compile(',(?= ")')
#match_end_2 = re.compile(' (?=[0-9a-zA-Z])')
match_brace = re.compile('(?<=[A-Za-z0-9]) }')


state_req = requests.get(prefix + state_xpath, verify=False)
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
    update_dict['status']['ports'][key] = {'pu' : p_status}


##########################################################
#
#       Log Rate
#
##########################################################


xpath = "<show><system><state><filter>sw.mgmt.runtime.lograte</filter></state>" \
        "</system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcw" \
        "M3JHUGVhRlNiY0dCR0srNERUQT09"

xpath_alt = "<show><system><state><filter>sw.logrcvr.runtime.write-lograte</fi" \
            "lter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh" \
            "0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"



# Check both version and platform to see if this is a physical device vs. VM

if (thisFW.os_ver[:3] == "8.0") and ("vm" not in thisFW.family):
    lograte_req = requests.get(prefix + xpath, verify=False)
    lograte_xml = et.fromstring(lograte_req.content)
    lograte_text = lograte_xml.find('./result').text
    lograte_text = lograte_text[lograte_text.find(':'):]
    lograte_text = lograte_text[2:]
    lograte_int = int(lograte_text, 16)
    update_dict['l'] = lograte_int
else:
    lograte_req = requests.get(prefix + xpath_alt, verify=False)
    lograte_xml = et.fromstring(lograte_req.content)
    lograte_text = lograte_xml.find('./result').text
    lograte_text = lograte_text[lograte_text.find(':'):]
    lograte_text = lograte_text[2:]
    update_dict['trend']['l'] = int(lograte_text)




##########################################################
#
#       Environmentals - Fans
#
##########################################################



if "vm" not in thisFW.family:
    xpath = "<show><system><state><filter>env.s*.fan.*</filter></state></syste" \
            "m></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3J" \
            "HUGVhRlNiY0dCR0srNERUQT09"

    match_end = re.compile(',(?= ")')
    match_begin = re.compile(': (?=[0-9a-fA-Z])')
    match_fan_slot = re.compile('(?<=env\.s)(.*)(?=\.fan)')
    match_fan_number = re.compile('(?<=fan\.)(.*)(?=:)')


    rate_req = requests.get(prefix + xpath, verify=False)
    rate_xml = et.fromstring(rate_req.content)
    rate_text = rate_xml.find('./result').text
    # print rate_text



    rate_text = rate_text.split('\n')

    for resp_string in rate_text:
        if resp_string == "":
            break
        label = resp_string[:resp_string.find('{')]
        fan_slot_number = re.search(match_fan_slot, label).group(0)
        fan_number = re.search(match_fan_number, label).group(0)
        resp_string = resp_string[resp_string.find('{'):] # Need to pull the slot/fan# for the line before here.
        resp_string = resp_string.replace('\'', '"')
        resp_string = resp_string.replace(', }', ' }')
        resp_string = resp_string.replace(', ]', ' ]')
        resp_string = re.sub(match_begin, ': "', resp_string)
        resp_string = re.sub(match_end, '", ', resp_string)
        j_line = ast.literal_eval(resp_string)
        f_string = "fan{}/{}".format(str(fan_slot_number), str(fan_number))
        if f_string not in update_dict['status']:
            update_dict['status'][f_string] = {}
        update_dict['status'][f_string]['alrm'] = str(j_line['alarm'])
        update_dict['status'][f_string]['rpm'] = int(j_line['avg'])




##########################################################
#
#       Environmentals - Power
#
##########################################################


if "vm" not in thisFW.family:
    xpath = "<show><system><state><filter>env.s*.power.*</filter></state></sys" \
            "tem></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM" \
            "3JHUGVhRlNiY0dCR0srNERUQT09"

    # Slot/Rail match criteria
    pwr_slot_match = re.compile('(?<=env\.s)(.*)(?=\.power)')
    pwr_rail_match = re.compile('(?<=power\.)(.*)(?=:)')

    # Match criteria for JSON formatting
    match_begin = re.compile(': (?=[0-9a-fA-Z])')
    match_end = re.compile(',(?= ")')
    match_end_2 = re.compile(' (?=})')


    pwr_req = requests.get(prefix + xpath, verify=False)
    pwr_xml = et.fromstring(pwr_req.content)
    pwr_text = pwr_xml.find('./result').text
    if pwr_text is None:
        print "No power data"
    else:
        pwr_text = pwr_text.split('\n')

    for line in pwr_text:
        if line == "":
            break
        label = line[:line.find('{')]
        pwr_slot_number = re.search(pwr_slot_match, label).group(0)
        pwr_rail_number = re.search(pwr_rail_match, label).group(0)
        line = line[line.find('{'):]
        line = line.replace('\'', '"')
        line = line.replace(', }', ' }')
        line = re.sub(match_begin, ': "', line)
        line = re.sub(match_end, '", ', line)
        p_string = "power{}/{}".format(str(pwr_slot_number), str(pwr_rail_number))
        j_line = ast.literal_eval(line)
        if p_string not in update_dict['status']:
            update_dict['status'][p_string] = {}
        update_dict['status'][p_string]['alrm'] = str(j_line['alarm'])


##########################################################
#
#       Environmentals - Thermal
#
##########################################################


if "vm" not in thisFW.family:
    xpath = "<show><system><state><filter>env.s*.thermal.*</filter></state></syste" \
            "m></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGV" \
            "hRlNiY0dCR0srNERUQT09"

    # Slot/Sensor match criteria

    match_therm_slot = re.compile('(?<=env\.s)(.*)(?=\.therm)')
    match_therm_sensor = re.compile(('(?<=mal\.)(.*)(?=:)'))

    # Match criteria for JSON formatting
    match_begin = re.compile(': (?=[A-Z0-9\-])')
    match_end = re.compile(',(?= ")')


    therm_req = requests.get(prefix + xpath, verify=False)

    therm_xml = et.fromstring(therm_req.content)
    therm_text = therm_xml.find('./result').text
    if therm_text == None:
        print "No thermal data"
    else:
        therm_text = therm_text.split('\n')

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
        j_line = ast.literal_eval(line)
        t_string = "thermal{}/{}".format(str(therm_slot_number), str(therm_sensor_number))
        if t_string not in update_dict['status']:
            update_dict['status'][t_string] = {}
        update_dict['status'][t_string]['alrm'] = str(j_line['alarm'])
        update_dict['status'][t_string]['d'] = str(j_line['desc'])
        update_dict['status'][t_string]['tm'] = float(j_line['avg'])

##########################################################
#
#       Environmentals - Disk Partitions
#
##########################################################




partition_xpath = "<show><system><state><filter>resource.s*.mp.partition</filte" \
                  "r></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpne" \
                  "mh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

match_begin = re.compile(': (?=[0-9a-fA-Z])')
match_end = re.compile(',(?= ")')
match_end_2 = re.compile(' (?=})')
match_brace = re.compile('(?<=[A-Za-z0-9]) }')


part_req = requests.get(prefix + partition_xpath, verify=False)
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
    if key not in update_dict['status']['environmentals']['mounts']:
        update_dict['status']['environmentals']['mounts'][key] = {}
    size = int(j_line[key]['size'], 16)
    used = int(j_line[key]['used'], 16)
    avail = size - used
    pct_used = round((float(used)/float(size))*100, 0)
    update_dict['status']['environmentals']['mounts'][key]['s'] = size
    update_dict['status']['environmentals']['mounts'][key]['u'] = used
    update_dict['status']['environmentals']['mounts'][key]['a'] = avail
    update_dict['status']['environmentals']['mounts'][key]['put'] = pct_used







##########################################################
#
#       Environmentals - Raid Status
#
##########################################################

# TODO: updatedict['status']['environmentals']['disk']['fake1']['fake2']['0']...

# sys.raid.s*.ld*.drives = for 0 and 1, include name ('n'), size('z') and status('s')
# status
# active sync = '1'



##########################################################
#
#       Log Forwarding
#
##########################################################


if thisFW.os_ver[:3] == "8.0":

    autotag = ['autotag', {'avg':'sw.logrcvr.autotag_avg_send_rate', 'sent':'sw.logrcvr.autotag_sent_count',
                'drop':'sw.logrcvr.autotag_drop_count'}]

    http = ['http', {'avg':'sw.logrcvr.http_avg_send_rate','sent':'sw.logrcvr.http_sent_count',
                 'drop':'sw.logrcvr.http_drop_count'}]

    raw = ['raw', {'avg':'sw.logrcvr.raw_avg_send_rate', 'sent':'sw.logrcvr.raw_sent_count',
                 'drop':'sw.logrcvr.raw_drop_count'}]

    email = ['email', {'avg':'sw.logrcvr.email_avg_send_rate', 'sent':'sw.logrcvr.email_sent_count',
                  'drop':'sw.logrcvr.email_drop_count'}]

    snmp = ['snmp', {'avg':'sw.logrcvr.snmp_avg_send_rate', 'sent':'sw.logrcvr.snmp_sent_count',
                 'drop':'sw.logrcvr.snmp_drop_count'}]

    syslog = ['syslog', {'avg':'sw.logrcvr.syslog_avg_send_rate', 'sent':'sw.logrcvr.syslog_sent_count',
                   'drop':'sw.logrcvr.syslog_drop_count'}]

    node_list = [autotag, http, raw, email, snmp, syslog]

    for node in node_list:
        for m_key in node[1]:
            xpath = "<show><system><state><filter>{}</filter></state></system></show>".format(node[1][m_key])
            node_req = requests.get(prefix + xpath + api_key, verify=False)
            node_xml = et.fromstring(node_req.content)
            node_text = node_xml.find('./result').text
            node_text = node_text[node_text.find(': ') + 2:]
            update_dict['status']['logging-external']['external'][node[0]][m_key] = int(node_text)

update_str = json.dumps(update_dict)

# print update_str
# print sys.getsizeof(update_dict)
# print sys.getsizeof(update_str)


pano_prefix = "http://10.3.4.63/api/?type=op"
# paramlist = {}
# datalist = {}
# paramlist['type'] = 'op'
# paramlist['key'] = 'LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09'
key = '&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09'

cmd = '&cmd=<monitoring><external-input><device>007200003295</device><data><![CDATA[{}]]></data></external-input></monitoring>'.format(update_str)
update_req = requests.get(pano_prefix + cmd + key, verify=False)
# print update_req.url
print update_req.content


