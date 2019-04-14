import pandas as pd
import sys
import socket
import fcntl
import struct
import math

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
self_ip = s.getsockname()[0]
s.close()

if len(sys.argv) < 1:
	raise Exception("not enough args")

if len(sys.argv) == 3:
	label = sys.argv[2]
else:
	label = -1

file_name = sys.argv[1]

df = pd.read_csv(file_name)

flow_col = df[['IP Src', 'IP Dst', 'TCP sport', 'TCP dport', 'IP proto']]

flows = []
data = []

for index, row in df.iterrows():

	if (row['TCP sport'] != "???") and (row['TCP dport'] != "???") and (row['IP proto'] != "???"):
		if (not math.isnan(float(row['TCP sport']))) or (not math.isnan(float(row['TCP dport']))) or (not math.isnan(float(row['IP proto']))):

			flow = (row['IP Src'], row['IP Dst'], row['TCP sport'], row['TCP dport'], row['IP proto'])

			if(flow[0] == self_ip):
				flow_ip = flow[1]
				c_port = row['TCP sport']
				s_port = row['TCP dport']
				t_prot = row['IP proto']
				sent = True
			else:
				flow_ip = flow[0]
				c_port = row['TCP dport']
				s_port = row['TCP sport']
				t_prot = row['IP proto']
				sent = False

			if (flow_ip, c_port, s_port, t_prot) not in flows:
				flows.append((flow_ip, c_port, s_port, t_prot))
				data.append([t_prot, 0, 0, 0, 0, 0])
			
			index = flows.index((flow_ip, c_port, s_port, t_prot))


			if math.isnan(row['IP len']):
				row['IP len'] = '0'
			if math.isnan(row['IP ttl']):
				row['IP ttl'] = '0'

			if sent:
				data[index][1] += int(row['IP len'])
				data[index][3] += int(row['IP ttl'])
			else:
				data[index][2] += int(row['IP len'])
				data[index][4] += int(row['IP ttl'])

			data[index][5] += 1

"""
for i in range(0, len(data)):
	print flows[i], data[i]
"""

for row in data:

	c = row[len(row) - 1] # count
	
	if c == 0:
		c = 1.0

	print row[0], ',', row[1]/c, ',', row[2]/c, ',', row[3]/c, ',', row[4]/c, ',', label












