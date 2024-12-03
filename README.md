# Go 实现的 [WireGuard](https://www.wireguard.com/)

这是一个用 Go 实现的 WireGuard。

## 使用方法

大多数 Linux 内核 WireGuard 用户习惯于使用 `ip link add wg0 type wireguard` 来添加接口。使用 wireguard-go 时，只需运行：


```
$ wireguard-go wg0
```

这将创建一个接口并将程序分离到后台运行。要删除接口，可以使用常规的 `ip link del wg0`，或者如果您的系统不支持直接删除接口，可以通过 `rm -f /var/run/wireguard/wg0.sock` 删除控制套接字，这样 wireguard-go 将会关闭。

要在不分离到后台的情况下运行 wireguard-go，请传递 `-f` 或 `--foreground` 参数：

```
$ wireguard-go -f wg0
```


当接口正在运行时，您可以使用 [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) 来配置它，以及常用的 `ip(8)` 和 `ifconfig(8)` 命令。

要启用更多日志记录，您可以设置环境变量 `LOG_LEVEL=debug`。

## 支持平台

### Linux

此程序可以在 Linux 上运行；但是，您应该使用内核模块，因为它更快且与操作系统集成得更好。有关安装说明，请参见 [安装页面](https://www.wireguard.com/install/)。

### macOS

此程序可以在 macOS 上运行，使用 utun 驱动程序。它尚不支持粘性套接字，并且由于 Darwin 的限制，无法支持 fwmarks。由于 utun 驱动程序无法使用任意接口名称，因此您必须使用 `utun[0-9]+` 来指定一个明确的接口名称，或者使用 `utun` 让内核为您选择。如果您选择了 `utun` 作为接口名称，并且定义了环境变量 `WG_TUN_NAME_FILE`，那么内核选择的接口实际名称将写入该变量指定的文件中。

### Windows

此程序可以在 Windows 上运行，但您应该通过更为 [功能完善的 Windows 应用程序](https://git.zx2c4.com/wireguard-windows/about/) 来使用它，后者使用此程序作为模块。

### FreeBSD

此程序可以在 FreeBSD 上运行。它尚不支持粘性套接字。Fwmark 被映射到 `SO_USER_COOKIE`。

### OpenBSD

此程序可以在 OpenBSD 上运行。它尚不支持粘性套接字。Fwmark 被映射到 `SO_RTABLE`。由于 tun 驱动程序不能使用任意接口名称，您必须使用 `tun[0-9]+` 来指定一个明确的接口名称，或者使用 `tun` 来让程序为您选择一个。如果您选择了 `tun` 作为接口名称，并且定义了环境变量 `WG_TUN_NAME_FILE`，那么内核选择的接口实际名称将写入该变量指定的文件中。

## 构建

此程序需要安装最新版本的 [Go](https://go.dev/)。



```
$ git clone https://github.com/Nort0nChen/wireguard-go
$ cd wireguard-go
$ make
```

## License

    Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
