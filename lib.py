import sys
import io
import ipaddress
from ipaddress import ip_address, ip_network

def decider(ruleList, line):
	#PACKET IN: <direction> <ip> <port> <flag>
	split = line.split()
	pkt_length = len(split)
	returner = ""

	if (pkt_length not in range(3,5)):
		sys.stderr.write("Invalid Packet: " + line + ". Ignoring Packet\n")
		return ""

	# parse packet
	pkt_direction = split[0]
	pkt_ip = split[1]
	pkt_port = split[2]

	pkt_rule = ''
	rule_num = 0
	for rule in ruleList:
		print(rule_num)
		rule_num += 1
		# RULE: <directon> <action> <ip> <port> [flag]
		rule_arg = rule.split()

		if (pkt_direction == rule_arg[1]) and (ip_address(pkt_ip) in ip_network(rule_arg[2])) and (pkt_port in rule_arg[3]) and (pkt_rule == ''):
			pkt_rule = "%d"%(rule_num+1)
			print('PACKET RULE APPLIED: ' + pkt_rule)

	return returner
	#OUT: <action>(<rule number>) <direction> <ip> <port> <flag>

# returns rule as string if valid
def ruleLine(line, counter):
	#<direction> <action> <ip> <port> [flag]
	split = line.split()
	length = len(split)
	returner = ""
	test = 0
	count = str(counter)

	# if comment, ignore
	if line[0] == '#':
		return
	elif length not in range(4,6):
		print(split)
		sys.stderr.write("Line " + count + ": Invalid rule, Ignoring Line\n")
		return ""
	else:
		direction = split[0]
		if direction not in {"in", "out"}:
			sys.stderr.write("Line " + count + ": Invalid Direction, Ignoring Line\n")
			return ""
		returner = direction + " "
		#------------------------------
		action = split[1]
		if action not in {"accept", "deny"}:
			sys.stderr.write("Line " + count + ": Invalid action, Ignoring Line\n")
			return ""
		returner = returner + action + " "
		#------------------------------
		iprange = split[2].split("/")
		if len(iprange) > 2:
			sys.stderr.write("Line " + count + ": Invalid CIDR Notation, Ignoring Line\n")
			return ""
		elif (split[2] == '*'):
			returner = returner + "* "
		elif len(iprange) == 2:
			try:
				iprangeint = int(iprange[1])
			except:
				sys.stderr.write("Line " + count + ": Accepts IPv4 format only, Ignoring Line\n")
				return ""
			if (iprangeint < 0 or iprangeint > 32):
				sys.stderr.write("Line " + count + ": Invalid IP Range, Ignoring Line\n")
				return ""
			elif (iprangeint == 0):
				returner = returner + "* "
			else:
				ip4 = iprange[0].split(".")
				if (len(ip4) != 4):
					sys.stderr.write("Line " + count + ": Invalid IP Format, Ignoring Line\n")
					return ""
				returner = returner + split[2] + " "
		#------------------------------
			try:
				ports = split[3].split(",")
				if (split[3] == "*"):
					pass
				else:
					for port in ports:
						test = int(port)
						if test not in range(0, 65536):
							sys.stderr.write("Line " + count + ": " + str(test) + " is not a valid port number, Ignoring Line\n")
							return ""
			except:
				sys.stderr.write("Line " + count + ": Supplied port not a number, Ignoring Line\n")
				return ""
			returner = returner + split[3] + " "
		#------------------------------
			if (length == 5):
				if (split[4] != "established"):
					sys.stderr.write("Line " + count + ": Invalid Flag, Ignoring Line\n")
					return ""
				returner = returner + split[4]

		return returner