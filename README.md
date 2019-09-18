# Camo

Camo is a VPN using HTTP/2 over TLS.

我理想的 proxy, 是所有流量都走 HTTPS, 一切看起来就像访问一个正常的网站一样.

[![Build Status](https://travis-ci.com/linfn/camo.svg?branch=master)](https://travis-ci.com/linfn/camo)
[![codecov](https://codecov.io/gh/linfn/camo/branch/master/graph/badge.svg)](https://codecov.io/gh/linfn/camo)

## Features

1. 使用 HTTP/2 over TLS 建立隧道, 将流量伪装成正常网站访问的流量
2. 内置 Let's Encrypt ACME
3. 支持 TLS 1.3 PSK 模式 (此模式下不再需要有效域名和证书)
4. 身份认证, 对无法通过身份认证的请求均返回 404
5. 支持 IPv4 和 IPv6
6. 连接到同一服务器的 client 可以通过私有 IP 相互访问

## Table of Contents

- [Camo](#camo)
  - [Features](#features)
  - [Table of Contents](#table-of-contents)
  - [Install](#install)
  - [Getting Started](#getting-started)
    - [Run Server with Docker](#run-server-with-docker)
      - [Standard Mode (Server)](#standard-mode-server)
      - [PSK Mode (Server)](#psk-mode-server)
      - [Enable IPv6 with Docker](#enable-ipv6-with-docker)
    - [Run Client](#run-client)
      - [Standard Mode (Client)](#standard-mode-client)
      - [PSK Mode (Client)](#psk-mode-client)
      - [IPv4 or IPv6 only](#ipv4-or-ipv6-only)
  - [Build](#build)
  - [License](#license)

## Install

你可以在 [release](https://github.com/linfn/camo/releases) 页面直接下载 `camo`.

或者使用 `camo` 的 docker 镜像:

```sh
# for server
docker pull linfn/camo
# for client
docker pull linfn/camo-client
```

或者使用 [go (1.12 or newer)](https://golang.org) 编译安装最新版本:

```sh
go get -u github.com/linfn/camo/cmd/...
```

## Getting Started

`camo` 有两种工作模式:

- **标准模式**: `camo` 使用 HTTPS 建立连接, 这意味着服务端需要配置有效的域名和证书 (一切都是为了让它看上去像在访问某个网站).
幸运的是 `camo` 内置了 `autocert` (via Let's Encrypt), 你不再需要手动申请和配置证书了.
- **PSK 模式**: 借助于 TLS 1.3 的 PSK 模式, 服务端可以不再需要域名和证书, 只通过配置的密钥便可建立安全的连接, 更加方便使用.

### Run Server with Docker

`camo` 建议你使用 [docker](https://get.docker.com/) 来运行 [camo-server](https://hub.docker.com/r/linfn/camo).

#### Standard Mode (Server)

将你的域名指向你的 IP 后, 启动 `camo-server`

```sh
docker run -d --cap-add=NET_ADMIN --device /dev/net/tun \
    -p 443:443 \
    -v $HOME/.cache/camo/certs:/camo/certs \
    --name camo \
    -e CAMO_PASSWORD=<password> \
    linfn/camo --autocert-host <hostname>
```

这里 `<hostname>` 是你使用的域名 (它应该正确的指向了你的 IP, 否则无法通过 ACME Challenge), 挂载的 `$HOME/.cache/camo/certs` 目录用于存储之后自动生成的证书.

#### PSK Mode (Server)

删除标准模式中的 `--autocert-host <hostname>` 参数, `camo-server` 就会使用 PSK 模式工作:

```sh
docker run -d --cap-add=NET_ADMIN --device /dev/net/tun \
    -p 443:443 \
    --name camo \
    -e CAMO_PASSWORD=<password> \
    linfn/camo
```

#### Enable IPv6 with Docker

有 3 种方式可以让 docker 容器在 IPv6 下工作:

1. 给容器分配一个 Public IPv6 地址 (from your public pool)
2. 使用 IPv6 NAT 模式
3. 使用 host network

这里主要介绍前面两种方式.

**Step 1**: 首先需要在 docker 中创建一个 IPv6 network

```sh
docker network create --ipv6 --subnet 2001:db8:1::/64 ipv6
```

这里 `2001:db8:1::/64` 是一个示例网段, 如果你使用 Public IP 模式 (方式一), 你需要把它替换到 vps 服务商提供给你的 Public IPv6 网段下;
如果你使用 NAT 模式 (方式二), 你可以自己配置一个私有网段, 例如 fd00:1::/64.

**Step 2**: 运行 `camo-server`

这里以 `camo` 的标准模式举例 (如果使用 PSK 模式, 只需删除 `--autocert-host <hostname>` 参数即可)

```sh
docker run -d --cap-add NET_ADMIN --cap-add SYS_MODULE \
    --device /dev/net/tun \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --sysctl net.ipv6.conf.default.forwarding=1 \
    --sysctl net.ipv6.conf.all.forwarding=1 \
    --network ipv6 \
    -p 443:443 \
    -v /lib/modules:/lib/modules:ro \
    -v $HOME/.cache/camo/certs:/camo/certs \
    --name camo \
    -e CAMO_PASSWORD=<password> \
    linfn/camo --autocert-host <hostname>
```

这里 `--cap-add SYS_MODULE` 和 `-v /lib/modules:/lib/modules:ro` 是为了让 `ip6tables` 有能力自动载入需要的内核模块.

**Step 3**:

如果你使用 Public IP 模式 (方式一), 为了让 Router 能够找到容器, 你需要启用 [NDP Proxy](https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol)

```sh
sysctl net.ipv6.conf.eth0.proxy_ndp=1
ip -6 neigh add proxy <IPv6 address of container> dev eth0
```

另外 (可选的), 你还可以使用 [ndppd](https://github.com/DanielAdolfsson/ndppd) 服务, 它能够为一个或多个网段提供 NDP Proxy.

如果你使用 NAT 模式 (方式二):

```sh
ip6tables -t nat -A POSTROUTING -s 2001:db8:1::/64 -j MASQUERADE
```

将这里的 `2001:db8:1::/64` 替换为 *Step 1* 中创建的 network 网段即可.

更多 IPv6 with Docker 的相关信息参考[这里](https://docs.docker.com/v17.09/engine/userguide/networking/default_network/ipv6/).

### Run Client

> NOTE: camo-client 目前仅支持 macOS 和 linux 平台, windows 平台的支持正在进行中

#### Standard Mode (Client)

使用标准模式启动 (需要 root 权限):

```sh
sudo camo-client -password <password> <hostname>
```

#### PSK Mode (Client)

使用 PSK 模式启动 (需要 root 权限):

```sh
sudo camo-client -psk -password <password> -resolve <ip[:port]> <fake_hostname>
```

这里 `fake_hostname` 可以填写任意的域名 (例如 github.com), 然后在 `-resolve` 后填写真实的服务器 ip 地址 (端口默认 443).

#### IPv4 or IPv6 only

`camo-client` 会创建一个 `tun` 设备, 并同时接管 IPv4 和 IPv6 流量 (如果服务器启用了 IPv6 的话), 可以通过 `-4` 或 `-6` flag 进行设置, 例如:

```sh
# IPv4 only
sudo camo-client -4 -password <password> <hostname>
# IPv6 only
sudo camo-client -6 -password <password> <hostname>
```

## Build

golang (1.12 or newer) required.

```sh
make
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
