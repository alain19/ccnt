ccnt
====

简介
----
  校园网认证客户端，适用于武汉大学的神州数码认证。
中国大陆地区校园网认证大多数是基于eap协议修改后的
私有协议，本程序仅仅实现了神州数码的认证过程，但
是可以方便地扩展。使用C++与Boost，依赖libpcap库
（Windows中是Winpcap）,可在Linux与Windows中运行。

注意
----
  本程序已在上述环境中测试通过，可以使用联网，但是
本程序不是一个完整的软件，仅仅是为了研究校园网认证
机制，若需要正常使用，请自行修改。

编译
----
*	注意项目依赖Boost与libpcap

1、Linux
*	(1) 安装libpcap相应的库
*	(2) 在项目目录下执行 make

2、Windows
*	(1) 需要首先安装WinPcap（www.winpcap.org）与
		Boost相应头文件与库，
*	(2) 将项目作为CodeBlocks工程打开，更改Boost
		头文件与库的search path，编译执行
*	(3) 项目中用到C++11的一些特性，需要较高版本
		的编译器支持
*	(4) 也可以直接编译，但要注意Codeblocks项目
		描述文件中的依赖关系与宏定义。

使用
----
	Windows下提供二进制执行文件，Linux下请自行编译

TODO
----
*	重构后，windows部分已经完成，linux部分尚未完成
*	信息输出还有问题，考虑以后添加log功能
