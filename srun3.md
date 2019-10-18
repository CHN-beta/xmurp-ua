**如果你不是从我的博客来的，那么这个文件对你没有用。**

* 修改拨号脚本。WinSCP 连接到路由器后，打开文件 `/lib/netifd/proto/ppp.sh`，这个文件就是拨号的脚本了。搜索 `username` 关键字，可以找到这样一句：

  ```bash
  		${username:+user "$username" password "$password"} \
  ```

* 把它修改成：

  ```bash
  		${username:+user "$(echo -e $username)" password "$password"} \
  ```

  保存，关闭 WinSCP。