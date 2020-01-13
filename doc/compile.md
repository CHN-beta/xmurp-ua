以下，我假定你至少稍有一点命令行基础，搞不清当前目录或者 `cp`、`rm` 都不会用的话，自己找资料。

同时，以下内容中的代码仅仅是示例，目的是让你明白怎么回事，而不是复制粘贴就可以。

#### 一般的编译方法

对于 18.06 以上的 SDK，照这个方法就行了。

* 在电脑上安装一个 64 位的 Linux 系统。安装成虚拟机或双系统都可以。嫌麻烦的话，推荐使用 Win10 的 Ubuntu 子系统（WSL）。如果想要顺便体验实体机，强烈推荐 deepin。我使用的是 kubuntu 19.10。

* 安装编译依赖项。

  ```bash
  sudo apt-get update && sudo apt-get install git-core build-essential libssl-dev libncurses5-dev unzip gawk subversion mercurial ccache tar ssh
  ```

  记得开代理，或者换源。

* 准备 SDK。

  必须使用与镜像完全对应的 SDK，而不能只是架构相同或者内核版本前三位相同。

  官方 OpenWrt 的 SDK 和固件放在同一个目录下。比如，WNDR4300 的固件下载地址为：

  ```
  http://downloads.openwrt.org/releases/18.06.1/targets/ar71xx/nand/openwrt-18.06.1-ar71xx-nand-wndr4300-ubi-factory.img
  ```

  打开网站：

  ```
  http://downloads.openwrt.org/releases/18.06.1/targets/ar71xx/nand/
  ```

  就可以找到对应 SDK 的下载地址。

  下载好 SDK 后，放到用户目录下，解压 SDK 并进入。

  ```bash
  cd ~ && tar xvf openwrt-sdk*.tar.xz && cd openwrt-sdk*
  ```

  （如果使用 WSL，可以将 SDK 放到 C 盘根目录，然后使用命令 `cd ~ && cp /mnt/c/*.tar.xz .` 将它复制到 WSL 中。）

* 下载 `xmurp-ua` 的源代码，并编译。

  ```bash
  git clone https://github.com/CHN-beta/xmurp-ua.git package/xmurp-ua
  make defconfig
  make package/xmurp-ua/compile V=sc
  ```

  编译好的包在 `bin` 中。

#### 增加编译参数

对于 18.06 以前的 SDK，编译的时候需要手动指定一些参数。参考[这篇文章](https://blog.csdn.net/wr132/article/details/78946200)。按照我的经验，一般来说，指定 `ARCH` 和 `CROSS-COMPILE` 就足够了。例如：

```bash
make package/xmurp-ua/compile V=sc ARCH=mips CROSS_COMPILE=/home/chn/Desktop/lede-sdk-17.01.5-ar71xx-generic_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-5.4.0_musl-1.1.16/bin/mips-openwrt-linux-musl-
```

#### 使用旧版 Makefile

对于 Openwrt 15.05（Chaos Calmer），Makefile 的格式与最新版本不同。使用 `Chaos_Calmer.Makefile` 代替 `Makefile` 再编译。

```bash
cp package/xmurp-ua/Chaos_Calmer.Makefile package/xmurp-ua/Makefile
```

#### 失效的 host 命令

我还遇到过这样的情况：

```
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

解决办法就是，用自己电脑上的来替换 SDK 里给的那些命令，然后重新编译。

```bash
rm -r staging_dir/host/bin
ln -s /usr/bin staging_dir/host/
rm -r build_dir/target-mips_24kc_musl-1.1.16/linux-ar71xx_generic/xmurp-ua
make package/xmurp-ua/compile V=sc ARCH=mips CROSS_COMPILE=/home/chn/Desktop/lede-sdk-17.01.5-ar71xx-generic_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dirtoolchain-mips_24kc_gcc-5.4.0_musl-1.1.16/bin/mips-openwrt-linux-musl-
```

#### ARCH 混乱

在给某个潘多拉编译的时候，发现在一些地方 `ARCH` 为 `mips` 而另一些地方为 `mipsel`。记得之前给某个版本的 LEDE 编译时也出现过类似的错误。用软链接解决。

```bash
cd build_dir
ln -s target-mipsel_1004kc+dsp_uClibc-1.0.x target-mips_1004kc+dsp_uClibc-1.0.x
cd ..
make package/xmurp-ua/compile V=sc ARCH=mips CROSS_COMPILE=/home/chn/Desktop/PandoraBox-SDK-ralink-mt7621_gcc-5.5.0_uClibc-1.0.x.Linux-x86_64-2019-02-01-git-0231ad4b5/staging_dir/toolchain-mipsel_1004kc+dsp_gcc-5.5.0_uClibc-1.0.x/bin/mipsel-openwrt-linux-
```

#### objtool 缺失

今天在 deepin 上编译时，遇到了下面的问题：

```
make[4]: *** No rule to make target 'tools/objtool/objtool', needed by '/home/chn/repo/xmurp-ua/debug/openwrt-sdk-18.06.5-x86-64_gcc-7.3.0_musl.Linux-x86_64/build_dir/target-x86_64_musl/linux-x86_64/xmurp-ua/xmurp-ua.o'.  Stop.
```

解决办法是，把系统的 objtool 复制过来，然后再编译。

```bash
mkdir ./build_dir/target-x86_64_musl/linux-x86_64/linux-4.14.151/tools/objtool
cp /usr/src/linux-headers-4.15.0-30deepin-generic/tools/objtool/objtool ./build_dir/target-x86_64_musl/linux-x86_64/linux-4.14.151/tools/objtool/
```