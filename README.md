**不允许商业使用。** 希望某些“路由器团队”（实际上是宣传得吹上天、技术连我都不如的垃圾）赚钱的时候摸一下自己的良心。

---

喵喵喵，这里是一个修改 UA 的小模块。细致地讲，就是用在 OpenWrt 上修改发给外网 80 端口 GET 和 POST 请求的 UA 字段为 `XMURP/1.0` 再加很多个空格的内核模块，用来防止学校检测到使用代理（接路由器）。当然，你改一下 `Makefile`，用到其它 Linux 系统上也是可以的。如果你不了解 OpenWrt 的食用方法或者还是不明白这个插件是用来干什么的的话，可以看[这里](https://catalog.chn.moe/文章/教程/OpenWrt/在厦大宿舍安装路由器.html)。如果你不知道怎么编译，可以把 SDK 发给我我给你编译。如果要自己编译，看[这里](compile.md)。如果你使用官方稳定版，我把编译好的丢到[这里](https://github.com/CHN-beta/rkp-build)了，自取。

到现在为止，在 `4.x` 和 `3.x` 的内核上好像用得都没问题。

27 及以前的版本会导致路由器随机卡死，注意更新到最新版本。

这个模块因为设计上的缺陷，不能修改到所有的 UA，只能修改绝大多数的，对于厦门大学的情况，够用了。

如果有一些包不希望被改 UA，只要在防火墙规则里将 MARK 的第九位设置为 1 就可以了。例如：

```
iptables -t mangle -A PREROUTING -p tcp -m tcp --dport 80 -m mac --mac-source f8:94:c2:85:e8:14 -j MARK --set-xmark 0x100/0x100
```

在之前的版本中，使用的是 `0x1/0x1` 位，但是与 luci-app-shadowsocks 冲突，所以改到了 `0x100/0x100`。

另外，不要在 luci 中启用 flow offloading（流量分载，即 nat 加速），否则这个模块会失效。可以通过下面的命令（二选一，不需要两句都写）来对不需要这个模块的流量启用。

```
iptables -t filter -I FORWARD -p tcp ! --dport 80 ! --sport 80 -m conntrack --ctstate RELATED,ESTABLISHED -j FLOWOFFLOAD --hw
iptables -t filter -I FORWARD -p tcp ! --dport 80 ! --sport 80 -m conntrack --ctstate RELATED,ESTABLISHED -j FLOWOFFLOAD
```

两句的区别的话，大概是前者用硬件，后者用软件。具体的东西我也不熟悉。

---

有人问我为啥不能编译个二进制文件放出来，因为这是内核模块啊，和大多的 OpenWrt 模块是不一样的，要和内核版本（精确到 commit id）严格对应。至于为啥要写到内核里，是历史原因：最开始我想修改 ipid，这当然在内核里更方便；后来又想改 ua，就继续写在内核里了。最开始的功能还很简单，后来代码一点点变复杂了，我也后悔开始时写到内核里了。