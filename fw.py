import sys
import io
import lib


if __name__ == "__main__":
	if len(sys.argv) == 2:
		config_file = sys.argv[1]
	else:
		sys.stderr.write("Usage: ./client fw.py [rule_file]\n")
		sys.exit(1)
	
	# open rule config_file
	try:
		f = open(sys.argv[1],'rb')
	except:
		sys.stderr.write("Error reading rule file\n")
		sys.exit(1)

	ruleList = []
	#reading rules
	sys.stderr.write("-------------------------------\n")
	sys.stderr.write("RULES:" + "\n")
	with open(sys.argv[1], 'r') as f:
		for line_count, line in enumerate(f):
			rule = lib.ruleLine(line, line_count)
			# add rule to ruleList
			ruleList.append(rule)
			if rule != '':
				sys.stderr.write("(%d)"%(line_count+1) + " " + ruleList[len(ruleList)-1] + "\n")
	
	sys.stderr.write("-------------------------------\n")
	sys.stderr.write("READING PACKETS:\n")

	for line in sys.stdin:
		# action decided for packet
		data = lib.decider(ruleList, line)
		sys.stdout.write(data)