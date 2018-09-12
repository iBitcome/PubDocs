# Cycript

手机版本：IOS 11.3

越狱工具：Electra 11.3.1开发者版

## 安装

通过dpkg -i命令安装Cycript的deb包，但是报如下错误：

```

iPhone:~ root# 
iPhone:~ root# dpkg -i cycript_0.9.501_iphoneos-arm.deb 
Selecting previously unselected package cycript.
(Reading database ... 1186 files and directories currently installed.)
Preparing to unpack cycript_0.9.501_iphoneos-arm.deb ...
Unpacking cycript (0.9.501) ...
dpkg: dependency problems prevent configuration of cycript:
 cycript depends on apr-lib; however:
  Package apr-lib is not installed.
 cycript depends on readline; however:
  Package readline is not installed.
 cycript depends on adv-cmds; however:
  Package adv-cmds is not installed.

dpkg: error processing package cycript (--install):
 dependency problems - leaving unconfigured
Errors were encountered while processing:
 cycript
iPhone:~ root# 
iPhone:~ root# 

```

那么没办法，只能一个个的去安装依赖包，先安装了apr：

```
iPhone:~ root# dpkg -i apr-lib_1.3.3-2_iphoneos-arm.deb 
Selecting previously unselected package apr-lib.
(Reading database ... 1197 files and directories currently installed.)
Preparing to unpack apr-lib_1.3.3-2_iphoneos-arm.deb ...
Unpacking apr-lib (1.3.3-2) ...
Setting up apr-lib (1.3.3-2) ...

```
安装好以后再次安装Cycript发现错误只有两个了：

```
iPhone:~ root# dpkg -i cycript_0.9.501_iphoneos-arm.deb 
(Reading database ... 1203 files and directories currently installed.)
Preparing to unpack cycript_0.9.501_iphoneos-arm.deb ...
Unpacking cycript (0.9.501) over (0.9.501) ...
dpkg: dependency problems prevent configuration of cycript:
 cycript depends on readline; however:
  Package readline is not installed.
 cycript depends on adv-cmds; however:
  Package adv-cmds is not installed.

dpkg: error processing package cycript (--install):
 dependency problems - leaving unconfigured
Errors were encountered while processing:
 cycript
iPhone:~ root#
```
明显看到错误已经少了一个。继续安装readline：

```

iPhone:~ root# 
iPhone:~ root# 
iPhone:~ root# dpkg -i readline_6.0-8_iphoneos-arm.deb 
Selecting previously unselected package readline.
(Reading database ... 1203 files and directories currently installed.)
Preparing to unpack readline_6.0-8_iphoneos-arm.deb ...
Unpacking readline (6.0-8) ...
Setting up readline (6.0-8) ...
iPhone:~ root# 
iPhone:~ root# 

```

安装adv-cmds，但是报错：

```

iPhone:~ root# 
iPhone:~ root# dpkg -i adv-cmds_119-6_iphoneos-arm.deb  
Selecting previously unselected package adv-cmds.
(Reading database ... 1203 files and directories currently installed.)
Preparing to unpack adv-cmds_119-6_iphoneos-arm.deb ...
Unpacking adv-cmds (119-6) ...
dpkg: error processing archive adv-cmds_119-6_iphoneos-arm.deb (--install):
 trying to overwrite '/usr/bin/tabs', which is also in package ncurses 6.1
Errors were encountered while processing:
 adv-cmds_119-6_iphoneos-arm.deb
iPhone:~ root# 
iPhone:~ root# 

```


























