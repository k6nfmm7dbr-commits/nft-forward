package connection

import "net"

// LocalIPs 返回本机所有接口地址（含回环）的字符串集合。
//
// 用途：conntrack 的原方向元组是 src=发起方 dst=目的方。服务器**自身发起**的
// 出站连接（例如 curl https://example.com、apt update）其 dport 可能恰好等于
// 某条转发规则的监听端口（443/80 极常见）。若不排除，这类流会被策略层误判成
// 「该规则的客户端」：占用 IP slot、虚报在线 IP，IP 限制开启时把真实用户挤掉。
//
// 归一化用 net.IP.String()，与 conntrack 解析侧一致（后者取 conntrack 的
// src= 字段原文，内核输出的也是规范形式），因此 IPv6 缩写可直接比较。
func LocalIPs() (map[string]bool, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(addrs)+2)
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			if v.IP != nil {
				out[v.IP.String()] = true
			}
		case *net.IPAddr:
			if v.IP != nil {
				out[v.IP.String()] = true
			}
		}
	}
	// 回环显式补齐：部分容器/精简环境 InterfaceAddrs 可能不含 lo。
	out["127.0.0.1"] = true
	out["::1"] = true
	return out, nil
}
