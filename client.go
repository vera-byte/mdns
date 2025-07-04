package mdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ServiceEntry 表示发现的服务项
// 包含名称、主机、地址、端口、TXT 信息等
// Addr 和 AddrV6 已弃用，建议使用 AddrV4/AddrV6IPAddr
// sent 标记是否已发送到用户 channel
// hasTXT 表示是否包含 TXT 信息（用于判断完整性）
type ServiceEntry struct {
	Name         string
	Host         string
	AddrV4       net.IP
	AddrV6       net.IP // @Deprecated
	AddrV6IPAddr *net.IPAddr
	Port         int
	Info         string
	InfoFields   []string

	Addr net.IP // @Deprecated

	hasTXT bool
	sent   bool
}

// 判断服务项是否包含完整数据（Addr、Port、TXT）
func (s *ServiceEntry) complete() bool {
	return (s.AddrV4 != nil || s.AddrV6 != nil || s.Addr != nil) && s.Port != 0 && s.hasTXT
}

// 查询参数配置结构
// 包括服务名、查询超时、多播接口、是否启用 IPv4/6 等
// Entries 是结果通道，接收服务项
// Logger 可指定自定义日志记录器
type QueryParam struct {
	Service             string
	Domain              string
	Timeout             time.Duration
	Interface           *net.Interface
	Entries             chan<- *ServiceEntry
	WantUnicastResponse bool
	DisableIPv4         bool
	DisableIPv6         bool
	Logger              *log.Logger
}

// 返回默认查询参数
func DefaultParams(service string) *QueryParam {
	return &QueryParam{
		Service:             service,
		Domain:              "local",
		Timeout:             time.Second,
		Entries:             make(chan *ServiceEntry),
		WantUnicastResponse: false,
		DisableIPv4:         false,
		DisableIPv6:         false,
	}
}

// 发起 mDNS 查询（使用默认 context）
func Query(params *QueryParam) error {
	return QueryContext(context.Background(), params)
}

// 发起带上下文的 mDNS 查询，支持取消
func QueryContext(ctx context.Context, params *QueryParam) error {
	if params.Logger == nil {
		params.Logger = log.Default()
	}

	client, err := newClient(!params.DisableIPv4, !params.DisableIPv6, params.Logger)
	if err != nil {
		return err
	}
	defer client.Close()

	go func() {
		select {
		case <-ctx.Done():
			client.Close()
		case <-client.closedCh:
			return
		}
	}()

	if params.Interface != nil {
		if err := client.setInterface(params.Interface); err != nil {
			return err
		}
	}

	if params.Domain == "" {
		params.Domain = "local"
	}
	if params.Timeout == 0 {
		params.Timeout = time.Second
	}

	return client.query(params)
}

// 快捷查询方法，使用默认参数
func Lookup(service string, entries chan<- *ServiceEntry) error {
	params := DefaultParams(service)
	params.Entries = entries
	return Query(params)
}

// client 表示 mDNS 查询客户端，封装了 socket 和查询状态
// 同时持有 IPv4 和 IPv6 的单播/多播连接
// closed 表示是否已关闭，closedCh 用于监听关闭事件
type client struct {
	use_ipv4 bool
	use_ipv6 bool

	ipv4UnicastConn *net.UDPConn
	ipv6UnicastConn *net.UDPConn

	ipv4MulticastConn *net.UDPConn
	ipv6MulticastConn *net.UDPConn

	closed   int32
	closedCh chan struct{}

	log *log.Logger
}

// 创建新客户端，绑定单播/多播端口
func newClient(v4 bool, v6 bool, logger *log.Logger) (*client, error) {
	if !v4 && !v6 {
		return nil, fmt.Errorf("必须启用 IPv4 或 IPv6 查询")
	}

	var uconn4, uconn6 *net.UDPConn
	var mconn4, mconn6 *net.UDPConn
	var err error

	if v4 {
		uconn4, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			logger.Printf("[ERR] mdns: 绑定 udp4 失败: %v", err)
		}
	}
	if v6 {
		uconn6, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
		if err != nil {
			logger.Printf("[ERR] mdns: 绑定 udp6 失败: %v", err)
		}
	}
	if uconn4 == nil && uconn6 == nil {
		return nil, fmt.Errorf("未能绑定任何单播 UDP 端口")
	}

	if v4 {
		mconn4, err = net.ListenMulticastUDP("udp4", nil, ipv4Addr)
		if err != nil {
			logger.Printf("[ERR] mdns: 绑定多播 udp4 失败: %v", err)
		}
	}
	if v6 {
		mconn6, err = net.ListenMulticastUDP("udp6", nil, ipv6Addr)
		if err != nil {
			logger.Printf("[ERR] mdns: 绑定多播 udp6 失败: %v", err)
		}
	}
	if mconn4 == nil && mconn6 == nil {
		return nil, fmt.Errorf("未能绑定任何多播 UDP 端口")
	}

	if uconn4 == nil || mconn4 == nil {
		logger.Printf("[INFO] mdns: IPv4 单播或多播监听失败")
		uconn4, mconn4, v4 = nil, nil, false
	}
	if uconn6 == nil || mconn6 == nil {
		logger.Printf("[INFO] mdns: IPv6 单播或多播监听失败")
		uconn6, mconn6, v6 = nil, nil, false
	}
	if !v4 && !v6 {
		return nil, fmt.Errorf("至少启用 IPv4 或 IPv6 之一")
	}

	c := &client{
		use_ipv4:          v4,
		use_ipv6:          v6,
		ipv4MulticastConn: mconn4,
		ipv6MulticastConn: mconn6,
		ipv4UnicastConn:   uconn4,
		ipv6UnicastConn:   uconn6,
		closedCh:          make(chan struct{}),
		log:               logger,
	}
	return c, nil
}

// 关闭客户端，释放所有资源
func (c *client) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil
	}
	c.log.Printf("[INFO] mdns: 正在关闭客户端 %v", *c)
	close(c.closedCh)

	if c.ipv4UnicastConn != nil {
		c.ipv4UnicastConn.Close()
	}
	if c.ipv6UnicastConn != nil {
		c.ipv6UnicastConn.Close()
	}
	if c.ipv4MulticastConn != nil {
		c.ipv4MulticastConn.Close()
	}
	if c.ipv6MulticastConn != nil {
		c.ipv6MulticastConn.Close()
	}
	return nil
}

// 设置客户端使用的多播网卡接口
func (c *client) setInterface(iface *net.Interface) error {
	if c.use_ipv4 {
		p := ipv4.NewPacketConn(c.ipv4UnicastConn)
		if err := p.SetMulticastInterface(iface); err != nil {
			return err
		}
		p = ipv4.NewPacketConn(c.ipv4MulticastConn)
		if err := p.SetMulticastInterface(iface); err != nil {
			return err
		}
	}
	if c.use_ipv6 {
		p2 := ipv6.NewPacketConn(c.ipv6UnicastConn)
		if err := p2.SetMulticastInterface(iface); err != nil {
			return err
		}
		p2 = ipv6.NewPacketConn(c.ipv6MulticastConn)
		if err := p2.SetMulticastInterface(iface); err != nil {
			return err
		}
	}
	return nil
}

// msgAddr 封装解析后的 DNS 消息和来源地址
// 用于内部 channel 通信（接收线程 -> 解析线程）
type msgAddr struct {
	msg *dns.Msg
	src *net.UDPAddr
}

// query 用于执行服务查询并将结果通过 channel 发送
func (c *client) query(params *QueryParam) error {
	// 构造服务名称，例如 _http._tcp.local.
	serviceAddr := fmt.Sprintf("%s.%s.", trimDot(params.Service), trimDot(params.Domain))

	// 启动响应监听协程，监听来自 IPv4 和 IPv6 的单播和多播连接
	msgCh := make(chan *msgAddr, 32)
	if c.use_ipv4 {
		go c.recv(c.ipv4UnicastConn, msgCh)
		go c.recv(c.ipv4MulticastConn, msgCh)
	}
	if c.use_ipv6 {
		go c.recv(c.ipv6UnicastConn, msgCh)
		go c.recv(c.ipv6MulticastConn, msgCh)
	}

	// 构造 DNS 查询报文，类型为 PTR（用于服务发现）
	m := new(dns.Msg)
	m.SetQuestion(serviceAddr, dns.TypePTR)
	// RFC 6762 §5.4 指定是否希望单播响应
	if params.WantUnicastResponse {
		m.Question[0].Qclass |= 1 << 15
	}
	m.RecursionDesired = false
	if err := c.sendQuery(m); err != nil {
		return err
	}

	// 保存正在解析的服务项（多条 DNS 响应可能组成一个完整服务）
	inprogress := make(map[string]*ServiceEntry)

	// 在指定超时时间内处理消息
	finish := time.After(params.Timeout)
	for {
		select {
		case resp := <-msgCh:
			var inp *ServiceEntry
			for _, answer := range append(resp.msg.Answer, resp.msg.Extra...) {
				switch rr := answer.(type) {
				case *dns.PTR:
					inp = ensureName(inprogress, rr.Ptr)
				case *dns.SRV:
					if rr.Target != rr.Hdr.Name {
						alias(inprogress, rr.Hdr.Name, rr.Target)
					}
					inp = ensureName(inprogress, rr.Hdr.Name)
					inp.Host = rr.Target
					inp.Port = int(rr.Port)
				case *dns.TXT:
					inp = ensureName(inprogress, rr.Hdr.Name)
					inp.Info = strings.Join(rr.Txt, "|")
					inp.InfoFields = rr.Txt
					inp.hasTXT = true
				case *dns.A:
					inp = ensureName(inprogress, rr.Hdr.Name)
					inp.Addr = rr.A
					inp.AddrV4 = rr.A
				case *dns.AAAA:
					inp = ensureName(inprogress, rr.Hdr.Name)
					inp.Addr = rr.AAAA
					inp.AddrV6 = rr.AAAA
					inp.AddrV6IPAddr = &net.IPAddr{IP: rr.AAAA}
					if rr.AAAA.IsLinkLocalUnicast() || rr.AAAA.IsLinkLocalMulticast() {
						inp.AddrV6IPAddr.Zone = resp.src.Zone
					}
				}
			}

			if inp == nil {
				continue
			}
			if inp.complete() {
				if inp.sent {
					continue
				}
				inp.sent = true
				select {
				case params.Entries <- inp:
				default:
				}
			} else {
				m := new(dns.Msg)
				m.SetQuestion(inp.Name, dns.TypePTR)
				m.RecursionDesired = false
				if err := c.sendQuery(m); err != nil {
					c.log.Printf("[ERR] mdns: 查询实例 %s 失败: %v", inp.Name, err)
				}
			}
		case <-finish:
			return nil
		}
	}
}

// sendQuery 发送 DNS 查询包到多播地址
func (c *client) sendQuery(q *dns.Msg) error {
	buf, err := q.Pack()
	if err != nil {
		return err
	}
	if c.ipv4UnicastConn != nil {
		_, err = c.ipv4UnicastConn.WriteToUDP(buf, ipv4Addr)
		if err != nil {
			return err
		}
	}
	if c.ipv6UnicastConn != nil {
		_, err = c.ipv6UnicastConn.WriteToUDP(buf, ipv6Addr)
		if err != nil {
			return err
		}
	}
	return nil
}

// recv 循环读取 UDP 包，解包成 DNS 消息并写入 channel
func (c *client) recv(l *net.UDPConn, msgCh chan *msgAddr) {
	if l == nil {
		return
	}
	buf := make([]byte, 65536)
	for atomic.LoadInt32(&c.closed) == 0 {
		n, addr, err := l.ReadFromUDP(buf)
		if atomic.LoadInt32(&c.closed) == 1 {
			return
		}
		if err != nil {
			c.log.Printf("[ERR] mdns: 读取数据包失败: %v", err)
			continue
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			c.log.Printf("[ERR] mdns: 解包数据失败: %v", err)
			continue
		}
		select {
		case msgCh <- &msgAddr{msg: msg, src: addr}:
		case <-c.closedCh:
			return
		}
	}
}

// ensureName 确保服务名称存在于 inprogress map 中
func ensureName(inprogress map[string]*ServiceEntry, name string) *ServiceEntry {
	if inp, ok := inprogress[name]; ok {
		return inp
	}
	inp := &ServiceEntry{Name: name}
	inprogress[name] = inp
	return inp
}

// alias 建立服务别名，将 dst 映射为 src 所指服务
func alias(inprogress map[string]*ServiceEntry, src, dst string) {
	srcEntry := ensureName(inprogress, src)
	inprogress[dst] = srcEntry
}
