我昨天花了一天时间，想要写一个船新的版本：它会监控所有的符合条件的 TCP 流，并且一个不落地把 UA 改掉。这样的程序原理上没什么难度，但是内核里只能用 C 写，啥都得自己动手（相比于 C++），于是非常痛苦。写了几百行，还远远没写完。（dev 分支）

我想起来，我写 mirism 的时候，看到好像用户态也有办法可以直接拿到转发的链路层封包而不需要等应用层数据都组装好了再给你端上来。我顺着这个思路找了找，然后就发现了确实有非常简便的办法，可以用 C++ STL。那我之前都写了个锤子啊。

总之，这个版本放弃维护，我哪天想写的时候会写个船新的版本出来。因为是用户态的，基本不依赖于内核，我可以给每个架构、闪存的路由器都编译一份。说不定还可以写一个 luci-app-xmurp 可以直接在后台改设置。自己再建个仓库，添加自定义源然后 opkg 就能装，美滋滋。

---

喵喵喵，这里是一个修改 UA 的小模块。细致地讲，就是用在 OpenWrt 上修改发给外网 80 端口 GET 和 POST 请求的 UA 字段 为`XMURP/1.0`再加很多个空格的内核模块，用来防止学校检测到使用代理（接路由器）。具体情况，百度“厦大路由”然后看我的简书文章就好了。在 WNDR4300 OpenWrt 18.06.1（内核 4.9.120）测试似乎没问题。前两天还适配了一下 4.14的内核。

如果有一些包不希望被改 UA，只要在防火墙规则里将 MARK 的第九位设置为 1 就可以了。例如：

```
iptables -t mangle -A PREROUTING -p tcp -m tcp --dport 80 -m mac --mac-source f8:94:c2:85:e8:14 -j MARK --set-xmark 0x100/0x100
```

在之前的版本中，使用的是 `0x1/0x1` 位，但是与 luci-app-shadowsocks 冲突，所以改到了 `0x100/0x100`。

另外，不要在 luci 中启用 flow offloading（流量分载，即 nat 加速），否则这个模块会失效。可以通过下面的命令（二选一，不需要两句都写）来对不需要这个模块的流量启用。

```
iptables -t filter -I FORWARD -p tcp ! --dport 80 -m conntrack --ctstate RELATED,ESTABLISHED -j FLOWOFFLOAD --hw
iptables -t filter -I FORWARD -p tcp ! --dport 80 -m conntrack --ctstate RELATED,ESTABLISHED -j FLOWOFFLOAD
```

两句的区别的话，大概是前者用硬件，后者用软件。具体的东西我也不熟悉。

---

在老旧版本（15.05）上编译时，尝试用 Makefile.cc 替换 Makefile。方法如下：

```bash
git clone git@github.com:CHN-beta/xmurp-ua.git package/xmurp-ua
cp package/xmurp-ua/Makefile.cc package/xmurp-ua/Makefile
ln -s ../feeds/base/package/utils package/utils
make defconfig
make package/xmurp-ua/compile V=sc ARCH=mips
```

---

还有人在 LEDE 17.05.5 上编译失败了。所以说，能用新的就用新的，旧的总是会出麻烦的问题。不要听信什么旧的稳定，我不信。

我把编译方法和解决的过程放到这里，供参考。

* 首先当然是正常编译：

  ```bash
  git clone git@github.com:CHN-beta/xmurp-ua.git package/xmurp-ua
  make defconfig
  make package/xmurp-ua/compile V=sc ARCH=mips CROSS_COMPILE=/home/chn/Desktop/lede-sdk-17.01.5-ar71xx-generic_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-5.4.0_musl-1.1.16/bin/mips-openwrt-linux-musl-
  ```

* 这时会看到这样的错误：

  ```bash
  .find.bin: loadlocale.c:129: _nl_intern_locale_data: Assertion `cnt < (sizeof (_nl_value_type_LC_TIME) / sizeof (_nl_value_type_LC_TIME[0]))' failed.
  .xargs.bin: loadlocale.c:129: _nl_intern_locale_data: Assertion `cnt < (sizeof (_nl_value_type_LC_TIME) / sizeof (_nl_value_type_LC_TIME[0]))' failed.
  Aborted (core dumped)
  Aborted (core dumped)
    MODPOST 0 modules
  .find.bin: loadlocale.c:129: _nl_intern_locale_data: Assertion `cnt < (sizeof (_nl_value_type_LC_TIME) / sizeof (_nl_value_type_LC_TIME[0]))' failed.
  .xargs.bin: loadlocale.c:129: _nl_intern_locale_data: Assertion `cnt < (sizeof (_nl_value_type_LC_TIME) / sizeof (_nl_value_type_LC_TIME[0]))' failed.
  .sed.bin: loadlocale.c:129: _nl_intern_locale_data: Assertion `cnt < (sizeof (_nl_value_type_LC_TIME) / sizeof (_nl_value_type_LC_TIME[0]))' failed.
  Aborted (core dumped)
  Aborted (core dumped)
  Aborted (core dumped)
  ```

  以 `.xargs.bin` 为例子。

  ```bash
  find | grep .xargs.bin
  ```

  得到

  ```bash
  ./staging_dir/host/bin/.xargs.bin
  ```

  看看这个目录里的内容

  ```bash
  ls staging_dir/host/bin
  ```

  所以，这个目录里准备的就是一些常用的命令，或许是因为担心宿主机上缺少某些或者用法不一样导致编译错误。初心是好的，但这毕竟是几年前的玩意儿，当时准备的 `find` 等工具放到现在的电脑上闪退了（如果是老电脑的话，说不定还能用）。

* 解决办法就是，用自己电脑上的工具来替换这些老旧的东西。

  ```bash
  rm -r staging_dir/host/bin
  ln -s /usr/bin staging_dir/host/
  ```

* 然后把原来编译一半的删掉，重新编译。

  ```bash
  rm -r build_dir/target-mips_24kc_musl-1.1.16/linux-ar71xx_generic/xmurp-ua
  make package/xmurp-ua/compile V=sc ARCH=mips CROSS_COMPILE=/home/chn/Desktop/lede-sdk-17.01.5-ar71xx-generic_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-5.4.0_musl-1.1.16/bin/mips-openwrt-linux-musl-
  ```

  搞定。

