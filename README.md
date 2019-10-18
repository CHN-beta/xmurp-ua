喵喵喵，这里是一个修改 UA 的小模块。细致地讲，就是用在 OpenWrt 上修改发给外网 80 端口 GET 和 POST 请求的 UA 字段为 `XMURP/1.0` 再加很多个空格的内核模块，用来防止学校检测到使用代理（接路由器）。当然，你改一下 `Makefile`，用到其它 Linux 系统上也是可以的。如果你不了解 OpenWrt 的食用方法或者还是不明白这个插件是用来干什么的的话，又或是不知道怎么编译这个模块，可以看[这里]([https://catalog.chn.moe/%E6%96%87%E7%AB%A0/%E6%95%99%E7%A8%8B/OpenWrt/%E5%9C%A8%E5%8E%A6%E5%A4%A7%E5%AE%BF%E8%88%8D%E5%AE%89%E8%A3%85%E8%B7%AF%E7%94%B1%E5%99%A8.html](https://catalog.chn.moe/文章/教程/OpenWrt/在厦大宿舍安装路由器.html))。

到现在为止，在 `4.x` 和 `3.x` 的内核上好像用得都没问题。

注意，这个模块因为设计上的缺陷，不能修改到所有的 UA，只能修改绝大多数的，对于厦门大学的情况，够用了。

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

  所以，这个目录里准备的就是一些宿主机上常用的命令，都是几年前的玩意儿，当时准备的 `find` 等工具放到现在的电脑上闪退了（如果是老系统的话，说不定还能用）。

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


---

有人问我为啥不能编译个二进制文件放出来，因为这是内核模块啊，和大多的 OpenWrt 模块是不一样的，要和内核版本（精确到 commit id）严格对应。至于为啥要写到内核里，是历史原因：最开始我想修改 ipid，这当然在内核里更方便；后来又想改 ua，就继续写在内核里了。最开始的功能还很简单，后来代码一点点变复杂了，我也后悔开始时写到内核里了。