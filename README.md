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
### 先使用encode.cpp对shellcode进行加密，如果把shellcode写道exe里请在Unseparation_shellcode.cpp的
