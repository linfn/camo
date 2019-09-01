# Camo

Camo is a VPN using HTTP/2 over TLS.

我理想的 proxy, 是所有流量都走 HTTPS, 一切看起来就像访问一个正常的网站一样.

## Features

1. 使用 HTTP/2 over TLS 建立隧道
2. 内置 Let's Encrypt ACME (需要配置一个有效的域名)
3. 身份认证, 对无法通过身份认证的请求均返回 404
4. 支持 IPv4 和 IPv6
5. 连接到同一服务器的 client 可以通过私有 IP 相互访问

## Getting Started

### Run Server with Docker

camo 内置了 autocert (via Let's Encrypt), 将你的域名指向你的 IP 后, 启动 `camo-server` 即可

```sh
docker run -d --cap-add=NET_ADMIN --device /dev/net/tun \
    -p 443:443 \
    -v $HOME/.cache/camo/certs:/root/.cache/camo/certs \
    --name camo \
    -e CAMO_PASSWORD=<password> \
    linfn/camo --autocert-host <hostname>
```

#### Enable IPv6 with Docker

有两种方式可以让 docker 容器在 IPv6 下工作:

1. 给容器分配一个 Public IPv6 地址 (from your public pool)
2. 使用 IPv6 NAT 模式

**Step 1**: 首先需要在 docker 中创建一个 IPv6 network

```sh
docker network create --ipv6 --subnet 2001:db8:1::/64 ipv6
```

这里 `2001:db8:1::/64` 是一个示例网段, 如果你使用 Public IP 模式 (方式一), 你需要把它替换到 vps 服务商提供给你的 Public IPv6 网段下;
如果你使用 NAT 模式 (方式二), 你可以自己配置一个私有网段, 例如 fd00:1::/64.

**Step 2**: 运行 `camo-server`

```sh
docker run -d --cap-add=NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --sysctl net.ipv6.conf.default.forwarding=1 \
    --sysctl net.ipv6.conf.all.forwarding=1 \
    --network ipv6 \
    -p 443:443 \
    -v $HOME/.cache/camo/certs:/root/.cache/camo/certs \
    --name camo \
    -e CAMO_PASSWORD=<password> \
    -e CAMO_ENABLE_IP6=true \
    linfn/camo --autocert-host <hostname>
```

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

**NOTE: camo-client 目前仅支持 macOS 和 linux 平台.**

使用 [go](https://golang.org) 获取 `camo-client`

```sh
go get github.com/linfn/camo/cmd/camo-client
```

启动 `camo-client` (需要 root 权限)

```sh
sudo camo-client -password <password> <hostname>
```

`camo-client` 会创建一个 `tun` 设备, 并同时接管 IPv4 和 IPv6 流量 (如果服务器启用了 IPv6 的话), 可以通过 `-4` 或 `-6` flag 进行设置

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
