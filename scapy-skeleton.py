from scapy.all import *
import socket 
import sys
from collections import OrderedDict
import pandas
import json

#arguments: label_number packet_count timout_val csv_to_write_to
if len(sys.argv) < 5:
    raise Exception("not enough args")


#create OrderedDict from list; elements are empty lists which will be pushed into by the callback function used for in sniff() 
csv = OrderedDict()

diction = ["Ethernet Src", "Ethernet Dst", "Ethernet Type", \
"IP Src", "IP Dst", "IP Version", "IP ihl", "IP tos", "IP len", "IP id", "IP flags", "IP frag", "IP ttl", "IP proto", "IP chksum", \
"IPv6 Src", "IPv6 Dst", "IPv6 Version", "IPv6 tc", "IPv6 fl", "IPv6 plen", "IPv6 nh", "IPv6 hlim", \
"TCP sport", "TCP dport", "TCP seq", "TCP ack", "TCP dataofs", "TCP reserved", "TCP flags", "TCP window", "TCP chksum", "TCP urgptr", "TCP options", \
"UDP sport", "UDP dport", "UDP len", "UDP chksum", \
"Raw", \
"time", \
"Label"]

for elem in diction:
    csv[elem] = []

#define unknow value and get label number
unknown = "???"
label = int(sys.argv[1])

#copy fields from packets into dictionary; use placeholder for NA values (ex: UDP fields when packet uses TCP) 
def fields_extraction(x):
    if "Ethernet" in x: 
        csv["Ethernet Src"].append(x["Ethernet"].src)
        csv["Ethernet Dst"].append(x["Ethernet"].dst)
        csv["Ethernet Type"].append(x["Ethernet"].type)
    else:
        csv["Ethernet Src"].append(unknown)
        csv["Ethernet Dst"].append(unknown)
        csv["Ethernet Type"].append(unknown)
    
    try:
        csv["IP Src"].append(x["IP"].src)
        csv["IP Dst"].append(x["IP"].dst)
        csv["IP Version"].append(x["IP"].version)
        csv["IP ihl"].append(x["IP"].ihl)
        csv["IP tos"].append(x["IP"].tos)
        csv["IP len"].append(x["IP"].len)
        csv["IP id"].append(x["IP"].id)
        csv["IP flags"].append(x["IP"].flags)
        csv["IP frag"].append(x["IP"].frag)
        csv["IP ttl"].append(x["IP"].ttl)
        csv["IP proto"].append(x["IP"].proto)
        csv["IP chksum"].append(x["IP"].chksum) 
    except:
        csv["IP Src"].append(unknown)
        csv["IP Dst"].append(unknown)
        csv["IP Version"].append(unknown)
        csv["IP ihl"].append(unknown)
        csv["IP tos"].append(unknown)
        csv["IP len"].append(unknown)
        csv["IP id"].append(unknown)
        csv["IP flags"].append(unknown)
        csv["IP frag"].append(unknown)
        csv["IP ttl"].append(unknown)
        csv["IP proto"].append(unknown)
        csv["IP chksum"].append(unknown) 
    
    try:
        csv["IPv6 Src"].append(x["IPv6"].src)
        csv["IPv6 Dst"].append(x["IPv6"].dst)
        csv["IPv6 Version"].append(x["IPv6"].version)
        csv["IPv6 tc"].append(x["IPv6"].tc)
        csv["IPv6 fl"].append(x["IPv6"].fl)
        csv["IPv6 plen"].append(x["IPv6"].plen)
        csv["IPv6 nh"].append(x["IPv6"].nh)
        csv["IPv6 hlim"].append(x["IPv6"].hlim)
    except:
        csv["IPv6 Src"].append(unknown)
        csv["IPv6 Dst"].append(unknown)
        csv["IPv6 Version"].append(unknown)
        csv["IPv6 tc"].append(unknown)
        csv["IPv6 fl"].append(unknown)
        csv["IPv6 plen"].append(unknown)
        csv["IPv6 nh"].append(unknown)
        csv["IPv6 hlim"].append(unknown)
    
    try:
        csv["TCP sport"].append(x["TCP"].sport)
        csv["TCP dport"].append(x["TCP"].dport)
        csv["TCP seq"].append(x["TCP"].seq)
        csv["TCP ack"].append(x["TCP"].ack)
        csv["TCP dataofs"].append(x["TCP"].dataofs)
        csv["TCP reserved"].append(x["TCP"].reserved)
        csv["TCP flags"].append(x["TCP"].flags)
        csv["TCP window"].append(x["TCP"].window)
        csv["TCP chksum"].append(x["TCP"].chksum)
        csv["TCP urgptr"].append(x["TCP"].urgptr)
        csv["TCP options"].append(x["TCP"].options)
    except:
        csv["TCP sport"].append(unknown)
        csv["TCP dport"].append(unknown)
        csv["TCP seq"].append(unknown)
        csv["TCP ack"].append(unknown)
        csv["TCP dataofs"].append(unknown)
        csv["TCP reserved"].append(unknown)
        csv["TCP flags"].append(unknown)
        csv["TCP window"].append(unknown)
        csv["TCP chksum"].append(unknown)
        csv["TCP urgptr"].append(unknown)
        csv["TCP options"].append(unknown)
    
    try:
        csv["UDP sport"].append(x["UDP"].sport)
        csv["UDP dport"].append(x["UDP"].dport)
        csv["UDP len"].append(x["UDP"].len)
        csv["UDP chksum"].append(x["UDP"].chksum)
    except:
        csv["UDP sport"].append(unknown)
        csv["UDP dport"].append(unknown)
        csv["UDP len"].append(unknown)
        csv["UDP chksum"].append(unknown)
    
    csv["Raw"].append(unknown)

    csv["time"].append(x.time)
    csv["Label"].append(label)
    

#sniff packets
sniff(prn = fields_extraction, filter = "(ip or ip6) && (tcp or udp)", count = int(sys.argv[2]), timeout = int(sys.argv[3]))

#convert final dictionary to a dataframe and write it out to a csv
pkt_frame = pandas.DataFrame().from_dict(csv)
pkt_frame.to_csv("./" + sys.argv[4])
