# ebhttps

#### 一 、介绍
ebhttps是首款基于eBPF技术的开源web应用防火墙，最大的优点是零配置、不需要导入SSL证书、不中断生产环境等。主要功能有：
        1. 恶意Web漏洞扫描
	    2. 数据库SQL注入
	    3. 跨站脚本攻击（XSS)
	    4、CC  & DDOS防护
	    5、密码暴力破解
	    6. 危险文件上传检测
	    7. 非法URL/文件访问
	    8. 兼容OWASP的ModSecurity正则规则
	    9. eBPF技术零配置，不需要证书、不影响生产环境、极高性能
	    10.无监督机器学习、自主生成对抗规则
	    .....	  

#### 二 、编译和运行
##### 1、技术原理
​    eBPF是一项革命性的技术，可以追踪任何应用和内核导出的函数，实现hook效果。ebhttps通过uprobe、kprobe等技术hook OpenSSL的SSL_read、SSL_write函数，直接从内存获取HTTPS明文请求数据做攻击检测。
##### 2、内核要求

​    eBPF是要求内核版本大于4.10，推荐2021年以后的linux发行版本：

    Ubuntu 20.10+
    Fedora 31+
    RHEL 8.2+
    Debian 11+

##### 3、编译要求
```
首先运行cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF确认系统支持BTF选项，并安装编译环境。
CentOS/Fedora: 
  	yum install elfutils-libelf-devel gcc make  	
Debian/Ubuntu:
  	apt-get install libelf-dev gcc make
直接make即可生成可执行文件ebhttps。
```


##### 4、运行（root权限）

    ./ebhttps -a 打印出所有HTTPS请求头
    ./ebhttps    仅打印攻击

```
成功运行如下所示：
OpenSSL path: /lib64/libssl.so.3
ebhttps start ok...sql injection attack example:  curl or wget https://www.baidu.com/?id=123' or 1='1
2024-01-28 13:21:08   [*ALERT*]  [942100] [GET /] STR:"123 or 1=1" Matched, SQL Injection Attack Detected via libinjection 
```


##### 5、攻击测试
```
   1.用nginx建立HTTPS服务器测试
  rules/main.rule默认加载了一条SQL语句检测规则，可以访问https://serverip/select.html?testsql=delete * from test
  或者用Kali系统的漏洞扫描器nikto运行：./nikto  -host serverip -ssl -port 443 -C all
  如果打印了报警记录，则代表正常！


  2.嫌麻烦可以用wget（CentOS/Fedora/Ubuntu）或者curl（debian）测试SQL注入或者XSS：
  wget https://www.baidu.com/?id=123' or 1='1
  wget https://www.baidu.com/?id=<script>alert(1);</script>
  wget https://www.baidu.com/?select.html?testsql=delete * from test
  如果无效请ldd /usr/bin/wget打印出的动态链接库，判断和ebhttps显示的OpenSSL库(libss.so.x)路径一致才可以。

  3、要测试DDOS攻击检测，可以用wrk等工具在相同环境测试比。
  wrk -c 25 -t 25 -d 10 https://127.0.0.1/
```

#### 三、商业版
商业版提供WEB管理界面，也可以开源：

1、 支持HTTP和HTTPS。

2 、 支持IP关联和XDP联动阻断恶意IP。

3 、 支持机器学习、智能语义分析等。

#### 四、实战演示地址

实战地址 [http://59.110.1.135/](http://59.110.1.135/)

#### 五、源码部署请加微信号4108863或者httpwaf

![](https://gitee.com/httpwaf/httpwaf/raw/master/img/wechat.png)

#### 六、来一张首页大图

![](https://gitee.com/httpwaf/httpwaf/raw/master/img/home.png)