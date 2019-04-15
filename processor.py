import pandas as pd
import sys
import socket
import fcntl
import struct
import math

# These lines get the ip address of the computer running this code
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

# Get the file and open it
file_name = sys.argv[1]
df = pd.read_csv(file_name)

flows = []
data = []

# For every packet...
for index, row in df.iterrows():
	# Check to see if the ports and protocol are valid
	if (row['TCP sport'] != "???") and (row['TCP dport'] != "???") and (row['IP proto'] != "???"):
		if (not math.isnan(float(row['TCP sport']))) or (not math.isnan(float(row['TCP dport']))) or (not math.isnan(float(row['IP proto']))):

			# Get the flow
			flow = (row['IP Src'], row['IP Dst'], row['TCP sport'], row['TCP dport'], row['IP proto'])

			# Determine if the flow is going in or out
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

			# If we haven't seen this flow from src to dest, add it to the list
			if (flow_ip, c_port, s_port, t_prot) not in flows:
				flows.append((flow_ip, c_port, s_port, t_prot))
				data.append([t_prot, 0, 0, 0, 0, 0])
			
			# Get the index of the flow we're working with
			index = flows.index((flow_ip, c_port, s_port, t_prot))

			# Check validity if IP length and ttl
			if not ((isinstance(row['IP len'], int) or (isinstance(row['IP len'], int)))):
				row['IP len'] = '0'
			if not ((isinstance(row['IP ttl'], int) or (isinstance(row['IP ttl'], int)))):
				row['IP ttl'] = '0'

			# Add the data to the relevent columns (Either in or out)
			if sent:
				data[index][1] += int(row['IP len'])
				data[index][3] += int(row['IP ttl'])
			else:
				data[index][2] += int(row['IP len'])
				data[index][4] += int(row['IP ttl'])

			# Increment the the tracked amount of packets for a flow
			data[index][5] += 1


for row in data:

	# Get the number of packets used to track a flow
	c = row[len(row) - 1] # count
	
	# Safety, don't divide by zero
	if c == 0:
		c = 1.0

	# Print the average for each row, except the label & transmission protocol
	print row[0], ',', row[1]/c, ',', row[2]/c, ',', row[3]/c, ',', row[4]/c, ',', label












