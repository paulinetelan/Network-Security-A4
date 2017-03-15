import os
import subprocess
import sys
import time
import io

def decider(ruleList, line):
	#IN: <direction> <ip> <port> <flag>
	split = line.strip().lower().split(" ")
	length = len(split)
	returner = ""

	if (len(split) not in range(3,5):
		sys.stderr.write("Invalid Packet: " + line + ". Ignoring Packet\n")
		return ""
	action = split[0]
	ip_pattern = split[1]
	ports = split[2].split(",")
	
	return ""
	#OUT: <action>(<rule number>) <direction> <ip> <port> <flag>

def ruleLine(line,counter):
	#<direction> <action> <ip> <port> [flag]
	split = line.split("#")[0].strip().lower().split(" ")
	length = len(split)
	returner = ""
	test = 0
	count = str(counter)
	if length not in range(4,6):
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
		returner = action + " "
		#------------------------------
		iprange = split[2].split("/")
		if len(iprange) > 2:
			sys.stderr.write("Line " + count + ": Invalid CIDR Notation, Ignoring Line\n")
			return ""
		elif (iprange[0] == "*"):
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
				else:
					try:
						i = 0
						while (i < (iprangeint // 8)):
							returner = returner + "{0:08b}".format(int(ip4[i]))
							i = i+1
						j = iprangeint % 8
						if (j != 0):
							returner = returner + "{0:08b}".format(int(ip4[i]))[:j] + " "
						else:
							returner = returner + " "
					except:
						sys.stderr.write(asdasd + "Line " + count + ": Accepts IPv4 format only2, Ignoring Line\n")
						return ""
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

if __name__ == "__main__":
	if len(sys.argv) == 2:
		config_file = sys.argv[1]
	else:
		sys.stderr.write("Usage: ./client fw.py [rule_file]\n")
		sys.exit(1)
	
	try:
		f = open(sys.argv[1],'rb')
	except:
		sys.stderr.write("Error reading rule file\n")
		sys.exit(1)

	ruleList = []
	#reading rules
	sys.stderr.write("Rules parsed:" + "\n")
	with open(sys.argv[1], 'r') as f:
		for count,line in enumerate(f):
			ruleList.append(ruleLine(line,count))
			sys.stderr.write(ruleList[count] + "\n")

	while True:
		line = sys.stdin.buffer.read()
		data = decider(ruleList, line)
		sys.stdout.buffer.write(data)