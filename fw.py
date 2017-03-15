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
	sys.stderr.write("Rules parsed:" + "\n")
	with open(sys.argv[1], 'r') as f:
		for count,line in enumerate(f):
			# add rule to ruleList
			ruleList.append(lib.ruleLine(line,count))
			sys.stderr.write(ruleList[count] + "\n")

	while True:
		line = sys.stdin.buffer.read()
		data = lib.decider(ruleList, line)
		sys.stdout.buffer.write(data)