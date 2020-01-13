### 加载模块

因为还没有经过足够的测试，因此模块默认不启动，需要手动加载或者手动设置开机启动。

手动加载、卸载模块的方法是：

```bash
# 加载模块，所有参数都使用默认值，重启后不会自动加载
insmod xmurp-ua
# 使用自定义参数加载模块，没有指定的参数仍然使用默认，支持的参数见下文
insmod xmurp-ua 参数1=值1 参数2=值2
# 卸载模块，不需要指定参数
rmmod xmurp-ua
```

设置开机启动的方法是，将下面的内容放到 `/etc/modules.d/99-xmurp-ua` 中：

```
xmurp-ua 参数1=值1 参数2=值2
```

同样，没有指定的参数会使用默认值。

### 支持的参数

默认的参数已经可以正常工作，只有需要设置例外或者调整什么的时候才需要自己指定参数。

* `str_preserve`：指定需要忽略的字符串，默认为空。推荐使用双引号套单引号的写法（可以兼容 ua 中带空格的问题），字符串之间用逗号隔开。例如：

  ```bash
  xmurp-ua str_preserve='"Windows NT,WeGame"'
  ```

  这样，所有包含“Windows NT”或“WeGame”的 ua 都会被放行。

* `autocapture`：是否自动根据端口号和 ip 判定是否捕获和如何处理，默认为 `y`（即”yes“）。可以设置成 `n`（即”no“），然后手动编写捕获规则，详细见下一条。

* `mark_capture` 和 `mark_ack`：用来配合防火墙自定义规则使用，让用户自己编写捕获的规则。只有当 `autocapture` 为 `n` 时，这两个参数才有意义。这两个参数的默认值分别为 `0x100`、`0x200`，它们的意义请看下面的示例：

  ```bash
  insmod xmurp-ua autocapture=n        # 关闭自动捕获

  iptables -t mangle -N ua_mod_req     # 标记从客户端发到服务端的包
  iptables -t mangle -N ua_mod_ans     # 标记从服务端发到客户端的包

  # 需要在三个链中都放置规则
  iptables -t mangle -A INPUT -p tcp --sport 80 -j ua_mod_ans
  iptables -t mangle -A OUTPUT -p tcp --dport 80 -j ua_mod_req
  iptables -t mangle -A FORWARD -p tcp --sport 80 -j ua_mod_ans
  iptables -t mangle -A FORWARD -p tcp --dport 80 -j ua_mod_req

  # 确认 ip 地址符合要求
  iptables -t mangle -A ua_mod_req ! -s 192.168.0.0/16 -j RETURN
  iptables -t mangle -A ua_mod_req -d 192.168.0.0/16 -j RETURN
  iptables -t mangle -A ua_mod_ans -s 192.168.0.0/16 -j RETURN
  iptables -t mangle -A ua_mod_ans ! -d 192.168.0.0/16 -j RETURN

  # 打上需要的标记，这里假定 mark_capture 为 0x100，mark_ack 为 0x200
  # 从客户端到服务端的包需要全部打上 mark_capture，从客户端到服务端的带 ack 标志的包需要打上 mark_capture 和 mark_ack
  iptables -t mangle -A ua_mod_req -j MARK --set-xmark 0x100/0x100
  iptables -t mangle -A ua_mod_ans -p tcp --tcp-flags ack -j MARK --set-xmark 0x300/0x300
  ```

  上面的规则实现的效果与 `autocapture` 置为 `y` 时完全一致。

* `time_keepalive`：间隔多长时间检查一次监控的 tcp 流的活动情况，连续两次检查之间没有活动过的流就有可能被释放掉。单位为秒，默认值是 `1200`，意思是一个流超过 20 分钟不活动就可能被清理掉。例如：

  ```bash
  xmurp-ua time_keepalive=3600
  ```

* `len_ua`：为了判断 ua 的情况，最多可以捕获多少个数据包，默认值为 `2`。这是为了兼容非 HTTP 协议的内容处理。按照一个数据包的应用层长度为 1000B 来估计，如果存在超过 1000 字节的 ua（一般是不会出现这样长的），就可能被认为不是 HTTP 协议而被放行。

* `verbose` 和 `debug`：在内核日志中打印更详细的信息，只是为了调试。默认值为 `n`。除非是软路由或者虚拟机，否则不要开，很容易卡死。