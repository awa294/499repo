from scapy.all import *
import socket 
import os
    
def fields_extraction(x):
    print x.sprintf("{IP:%IP.src%,%IP.dst%,}")
         #"{TCP:%TCP.sport%,%TCP.dport%,}"
         #"{UDP:%UDP.sport%,%UDP.dport%}")

     #print x.summary()
    
    #x.show()

    #use x.time for time information on the pkts

pkts = sniff(prn = fields_extraction, count = 10)

# print pkts[0].show()
