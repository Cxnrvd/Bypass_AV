# 这是一个能绕过绝大部分杀软、沙箱的木马样本
下面我会对木马所涉及的技术进行阐述我会针对shellcode和加载器两方面解释
## 加载器部分
### 1.反沙箱 
#### 众说周知反沙箱的检测常规就是针对主机的cpu、内存、硬盘等操作，但是我个人认为这样不妥因为一些杀软或云沙箱会检测反沙箱功能，会对一些敏感api进行监控从而被抓包，所以我的思路是对桌面的快捷方式检测比如qq、微信、钉钉这些常规使用的软件进行检测逃避云沙箱。
<img width="1918" height="990" alt="vt" src="https://github.com/user-attachments/assets/f6c4d58e-374d-428f-bf0b-73c3ef8233e8" />

###  2.ntdll的重载和api的动态调用

####  一般杀软的检测机制就是会对一些敏感的api上钩子那么我们通过ntdll的重载和api的动态调用技术就可以绕过钩子实现功能，ntdll重载这一块是从系统目录加载原始 ntdll.dll，将当前进程中被挂钩的 ntdll 代码段（.text 段）替换为原始代码，api动态调用是遍历目标dll的导出表使用hash匹配函数名获取目标函数的地址使用指针执行。

### 3.shellcode和加载器分离
#### shellcode除了编码绕过杀软还可以和加载器分离，就是shellcode都不在exe里杀软就挺难检测出问题。

## shellcode部分
### shellcode部分主要多层混淆处理 使用的是XOR+RC4+base64+mac多层处理，最后是mac地址格式存在是windows对mac格式字符串有一定的宽容性。 

## 使用方法
### 先使用encode.cpp对shellcode进行加密，如果把shellcode写道exe里请在Unseparation_shellcode.cpp的mac_shellcode数组里。如果想实现参数分离可以使用我编译好的exe+shellcode运行即可

#### 感谢阅读



### English version



This is a Trojan sample that can bypass the vast majority of antivirus software and sandboxes. Below, I will explain the technologies involved in the Trojan, focusing on both the shellcode and the loader.

## Loader Section
### 1. Anti-sandbox
It is well-known that the conventional detection of anti-sandbox functions is based on operations on the host's CPU, memory, hard disk, etc. However, I personally think this approach is not ideal because some antivirus software or cloud sandboxes will monitor anti-sandbox functions and keep an eye on sensitive APIs, which may lead to detection. Therefore, my idea is to detect desktop shortcuts, such as those for commonly used software like QQ, WeChat, and DingTalk, to evade cloud sandboxes. <img width="1918" height="990" alt="vt" src="https://github.com/user-attachments/assets/f6c4d58e-374d-428f-bf0b-73c3ef8233e8" />


### 2. Overloading of ntdll and Dynamic Invocation of APIs 

The detection mechanism of general anti-virus software is to hook some sensitive APIs. Therefore, we can bypass the hooks and achieve the function by using the ntdll overloading and dynamic API calling techniques. The ntdll overloading part involves loading the original ntdll.dll from the system directory and replacing the hooked ntdll code segment (.text segment) in the current process with the original code. The dynamic API calling is to traverse the export table of the target dll, match the function name using hash, obtain the address of the target function, and execute it using a pointer. 

### 3. Separation of Shellcode and Loader
#### Besides encoding to bypass antivirus software, shellcode can also be separated from the loader. If the shellcode is not included in the exe file, it becomes quite difficult for antivirus software to detect any issues. 

The shellcode section mainly undergoes multi-layer obfuscation processing, which involves XOR, RC4, base64, and MAC. The final output is in MAC address format, taking advantage of Windows' tolerance for MAC format strings. 

## Usage Method
### First, use encode.cpp to encrypt the shellcode. If you write the shellcode into an exe file, please place it in the mac_shellcode array in Unseparation_shellcode.cpp. If you want to achieve parameter separation, you can run the compiled exe + shellcode directly. 

Thank you for reading.
