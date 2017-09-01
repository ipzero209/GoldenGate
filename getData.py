#!/usr/bin/python

import requests
import xml.etree.ElementTree as et
import json
import re
import panFW
# -------- Remove below here --------
import sys
import pudb


from requests.packages.urllib3.exceptions import InsecureRequestWarning

thisFW = panFW.Device('009908000102', '10.8.49.20', '8.0.2', '7000')



# To suppress certificate warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

key = "&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"
prefix = "https://10.8.49.20/api/?type=op&cmd="

update_dict = {'trend':{}}
update_dict['trend']['slot'] = {}
update_dict['trend']['interface'] = {}

##########################################################
#
#       MP CPU
#
##########################################################

xpath = "<show><system><state><filter>sys.monitor.s*.mp.exports</filter></state></system></show>"


mp_cpu_req = requests.get(prefix + xpath + key, verify=False)
mp_cpu_xml = et.fromstring(mp_cpu_req.content)
mp_cpu_text = mp_cpu_xml.find('./result').text
mp_cpu_text = mp_cpu_text[mp_cpu_text.find('{'):]
mp_cpu_text = mp_cpu_text.replace('\'', '"')
mp_cpu_text = mp_cpu_text.replace(', }', ' }')
mp_cpu_json = json.loads(mp_cpu_text)
update_dict['trend']['mcp'] = int(mp_cpu_json['cpu']['1minavg'])
#update_string = update_string + "mcp:{},".format(mp_cpu_json['cpu']['1minavg'])




##########################################################
#
#       MP MEM
#
##########################################################

xpath = "<show><system><state><filter>resource.s*.mp.memory</filter></state></system></show>"

mp_mem_req = requests.get(prefix + xpath + key, verify=False)
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
used_mem_hex_str = mp_mem_json["used"]
used_mem_int = int(used_mem_hex_str, 16)
update_dict['trend']['mmm'] = used_mem_int
#update_string = update_string + "mmm:{},".format(used_mem_int)


##########################################################
#
#       DP CPU
#
##########################################################

xpath = "<show><system><state><filter>sys.monitor.s*.dp*.exports</filter></state></system></show>"



dp_cpu_req = requests.get(prefix + xpath + key, verify=False)
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
    if j_line:
        if slot_num not in update_dict['trend']['slot']:
            update_dict['trend']['slot'][slot_num] = {}
        if dp_num not in update_dict['trend']['slot'][slot_num]:
            update_dict['trend']['slot'][slot_num][dp_num] = {}
        update_dict['trend']['slot'][slot_num][dp_num]['dcp'] = int(j_line['cpu']['1minavg'])



##########################################################
#
#       Session Info
#
##########################################################

#TODO - Review all fields with David ('su, spu, etc')
xpath = "<show><system><state><filter>sw.mprelay.s*.dp*.stats.session</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"


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
    if j_line:
        if session_slot_number not in update_dict['trend']['slot']:
            update_dict['trend']['slot'][session_slot_number] = {}
        if session_dp_number not in update_dict['trend']['slot'][session_slot_number]:
            update_dict['trend']['slot'][session_slot_number][session_dp_number] = {}
        update_dict['trend']['slot'][session_slot_number][session_dp_number]['cps'] = int(j_line['cps_installed'])
        update_dict['trend']['slot'][session_slot_number][session_dp_number]['pps'] = int(j_line['throughput_pps'])
        update_dict['trend']['slot'][session_slot_number][session_dp_number]['su'] = int(j_line['session_util'])
        update_dict['trend']['slot'][session_slot_number][session_dp_number]['sa'] = int(j_line['session_active'])
        update_dict['trend']['slot'][session_slot_number][session_dp_number]['spu'] = int(j_line['session_ssl_proxy_util'])
        update_dict['trend']['slot'][session_slot_number][session_dp_number]['sm'] = int(j_line['session_max'])



##########################################################
#
#       Session Info
#
##########################################################


xpath = "<show><system><state><filter>sw.mprelay.s*.dp*.packetbuffers</filter></state></system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"


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
    update_dict['trend']['slot'][pkt_slot_number][pkt_dp_number]['pktb'] = int(j_line['hw-buf']['used'])
    update_dict['trend']['slot'][pkt_slot_number][pkt_dp_number]['pktd'] = int(j_line['pkt-descr']['used'])




##########################################################
#
#       Session Info
#
##########################################################


# NOTE: Rate is only supported on 8.0 and later.

rate_xpath = "<show><system><state><filter>sys.s*.p*.rate</filter></state></sy" \
             "stem></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXc" \
             "wM3JHUGVhRlNiY0dCR0srNERUQT09"
stats_xpath = "<show><system><state><filter>net.s*.eth*.stats</filter></state>" \
              "</system></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TG" \
              "M9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

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
        int_label = "ethernet{}/{}".format(str(rate_slot_number), str(rate_int_number))
        line = line[line.find('{'):]
        line = line.replace('\'', '"')
        line = line.replace(', }', ' }')
        line = re.sub(match_begin, ':"', line)
        line = re.sub(match_end, '",', line)
        line = re.sub(match_end_2, '"', line)
        j_line = json.loads(line)
        if int_label not in update_dict['trend']['interface']:
            update_dict['trend']['interface'][int_label] = {}
        update_dict['trend']['interface'][int_label]['txb'] = int(j_line['tx-bytes'])
        update_dict['trend']['interface'][int_label]['rxb'] = int(j_line['rx-bytes'])
        update_dict['trend']['interface'][int_label]['txpb'] = int(j_line['tx-broadcast'])
        update_dict['trend']['interface'][int_label]['rxpb'] = int(j_line['rx-broadcast'])
        update_dict['trend']['interface'][int_label]['txpu'] = int(j_line['tx-unicast'])
        update_dict['trend']['interface'][int_label]['rxpu'] = int(j_line['rx-unicast'])
        update_dict['trend']['interface'][int_label]['txpm'] = int(j_line['tx-multicast'])
        update_dict['trend']['interface'][int_label]['rxpm'] = int(j_line['rx-multicast'])







stats_req = requests.get(prefix + stats_xpath, verify=False)
stats_xml = et.fromstring(stats_req.content)
stats_text = stats_xml.find('./result').text
if stats_text == None:
    print "No status info"
stats_text = stats_text.split('\n')


for line in stats_text:
    if line == "":
        break
    label = line[:line.find('{')]
    stats_slot_number = re.search(match_stats_slot, label).group(0)
    stats_int_number = re.search(match_stats_interface, label).group(0)
    int_label = "ethernet{}/{}".format(str(stats_slot_number), str(stats_int_number))
    line = line[line.find('{'):]
    line = line.replace('\'', '"')
    line = line.replace(', }', ' }')
    j_line = json.loads(line)
    if int_label not in update_dict['trend']['interface']:
        update_dict['trend']['interface'][int_label] = {}
    update_dict['trend']['interface'][int_label]['txe'] = int(j_line['tx-errs'])
    update_dict['trend']['interface'][int_label]['rxe'] = int(j_line['rx-errs'])


print sys.getsizeof(update_dict)















