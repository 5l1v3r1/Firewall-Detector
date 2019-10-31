try:
	import os
	import sys
	from scapy.all import *
except ImportError as ie:
	print(ie)

os.system("clear")

try:
	host = input(">> [?] Enter Target Host: ")
	src_port = random.randint(1, 65535)
	min_port = input(">> [?] Enter Min Port: ")
	max_port = input(">> [?] Enter Max Port: ")
	ports = range(int(min_port), int(max_port)+1)
	RST = 0x4
	print(">> [*] Initiating A Tcp Ack Based Firewall Detector")
	print("*"*60)
	try:
		conf.verb = 0
		for port in ports:
			ACKpkt = (IP(dst=host)/TCP(sport=src_port, dport=port, flags="A"))
			ACKpkt_resp = sr1(ACKpkt, timeout=5)
			if(ACKpkt_resp == None):
				print ("Port " + str(port) + " Has A Stateful Firewall(FILTERED)!")
				print("="*60)
			elif(ACKpkt_resp.haslayer(TCP)):
				if(ACKpkt_resp.getlayer(TCP).flags == 0x4):
					pass
	except Exception as e:
		print(e)
except 	KeyboardInterrupt as ki:
	print(">> [!] Exiting")
	sys.exit()
