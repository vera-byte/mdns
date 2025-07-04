package mdns

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns" // 使用 miekg 的 DNS 库处理 DNS 包
)

const (
	ipv4mdns              = "224.0.0.251" // mDNS IPv4 组播地址
	ipv6mdns              = "ff02::fb"    // mDNS IPv6 组播地址
	mdnsPort              = 5353          // mDNS 默认端口号
	forceUnicastResponses = false         // 强制使用单播响应（通常是 false）
)

var (
	// IPv4 和 IPv6 的 UDP 地址对象
	ipv4Addr = &net.UDPAddr{IP: net.ParseIP(ipv4mdns), Port: mdnsPort}
	ipv6Addr = &net.UDPAddr{IP: net.ParseIP(ipv6mdns), Port: mdnsPort}
)

// Config 用于配置 mDNS 服务
type Config struct {
	Zone Zone // 必须提供，实现响应查询的接口

	Iface *net.Interface // 指定监听的网络接口（可以为空，默认使用系统接口）

	LogEmptyResponses bool        // 是否记录无响应的查询
	Logger            *log.Logger // 可选，使用自定义日志器
}

// Server 表示 mDNS 服务器，用于监听和响应查询
type Server struct {
	config *Config

	ipv4List *net.UDPConn // IPv4 监听连接
	ipv6List *net.UDPConn // IPv6 监听连接

	shutdown   int32         // 是否关闭标记
	shutdownCh chan struct{} // 关闭信号通道
}

// NewServer 创建一个新的 mDNS 服务器实例
func NewServer(config *Config) (*Server, error) {
	// 创建 IPv4 和 IPv6 的多播监听
	ipv4List, _ := net.ListenMulticastUDP("udp4", config.Iface, ipv4Addr)
	ipv6List, _ := net.ListenMulticastUDP("udp6", config.Iface, ipv6Addr)

	// 如果两个监听都失败则返回错误
	if ipv4List == nil && ipv6List == nil {
		return nil, fmt.Errorf("无法启动任何多播监听器")
	}

	if config.Logger == nil {
		config.Logger = log.Default()
	}

	s := &Server{
		config:     config,
		ipv4List:   ipv4List,
		ipv6List:   ipv6List,
		shutdownCh: make(chan struct{}),
	}

	// 分别启动 goroutine 来接收 IPv4 和 IPv6 数据
	if ipv4List != nil {
		go s.recv(s.ipv4List)
	}
	if ipv6List != nil {
		go s.recv(s.ipv6List)
	}

	return s, nil
}

// Shutdown 关闭服务器监听器
func (s *Server) Shutdown() error {
	if !atomic.CompareAndSwapInt32(&s.shutdown, 0, 1) {
		return nil // 已经关闭
	}

	close(s.shutdownCh)

	if s.ipv4List != nil {
		s.ipv4List.Close()
	}
	if s.ipv6List != nil {
		s.ipv6List.Close()
	}
	return nil
}

// recv 长时间运行的 goroutine，用于从指定 UDP 连接接收数据包
func (s *Server) recv(c *net.UDPConn) {
	if c == nil {
		return
	}
	buf := make([]byte, 65536) // 读取缓冲区

	for atomic.LoadInt32(&s.shutdown) == 0 {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			continue
		}
		// 解析并处理查询包
		if err := s.parsePacket(buf[:n], from); err != nil {
			s.config.Logger.Printf("[ERR] mdns: 解析查询失败: %v", err)
		}
	}
}

// parsePacket 解析接收到的 DNS 数据包
func (s *Server) parsePacket(packet []byte, from net.Addr) error {
	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil {
		s.config.Logger.Printf("[ERR] mdns: 解包失败: %v", err)
		return err
	}
	return s.handleQuery(&msg, from)
}

// handleQuery 处理 DNS 查询消息
func (s *Server) handleQuery(query *dns.Msg, from net.Addr) error {
	// 只处理 Opcode 为标准查询（0）的请求
	if query.Opcode != dns.OpcodeQuery {
		return fmt.Errorf("mdns: 接收到非标准查询 Opcode=%v: %v", query.Opcode, *query)
	}
	if query.Rcode != 0 {
		return fmt.Errorf("mdns: 接收到非零响应码 Rcode=%v: %v", query.Rcode, *query)
	}

	if query.Truncated {
		return fmt.Errorf("[ERR] mdns: 暂不支持截断标志的 DNS 请求: %v", *query)
	}

	var unicastAnswer, multicastAnswer []dns.RR

	// 遍历所有问题，获取多播和单播的响应记录
	for _, q := range query.Question {
		mrecs, urecs := s.handleQuestion(q)
		multicastAnswer = append(multicastAnswer, mrecs...)
		unicastAnswer = append(unicastAnswer, urecs...)
	}

	// 构造响应消息
	resp := func(unicast bool) *dns.Msg {
		id := uint16(0)
		if unicast {
			id = query.Id
		}
		answer := multicastAnswer
		if unicast {
			answer = unicastAnswer
		}
		if len(answer) == 0 {
			return nil
		}

		return &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:            id,
				Response:      true,
				Opcode:        dns.OpcodeQuery,
				Authoritative: true,
			},
			Compress: true, // 启用响应压缩
			Answer:   answer,
		}
	}

	// 日志记录：若未产生响应
	if s.config.LogEmptyResponses && len(multicastAnswer) == 0 && len(unicastAnswer) == 0 {
		questions := make([]string, len(query.Question))
		for i, q := range query.Question {
			questions[i] = q.Name
		}
		s.config.Logger.Printf("未命中响应记录: %s", strings.Join(questions, ", "))
	}

	// 发送多播响应
	if mresp := resp(false); mresp != nil {
		if err := s.sendResponse(mresp, from, false); err != nil {
			return fmt.Errorf("mdns: 发送多播响应失败: %v", err)
		}
	}
	// 发送单播响应
	if uresp := resp(true); uresp != nil {
		if err := s.sendResponse(uresp, from, true); err != nil {
			return fmt.Errorf("mdns: 发送单播响应失败: %v", err)
		}
	}
	return nil
}

// handleQuestion 处理单个 DNS 查询问题，返回多播和单播记录列表
func (s *Server) handleQuestion(q dns.Question) (multicastRecs, unicastRecs []dns.RR) {
	records := s.config.Zone.Records(q) // 通过 zone 获取记录

	if len(records) == 0 {
		return nil, nil
	}

	// 判断是否需要使用单播响应（qclass 的最高位表示单播）
	if q.Qclass&(1<<15) != 0 || forceUnicastResponses {
		return nil, records
	}
	return records, nil
}

// sendResponse 发送 DNS 响应消息
func (s *Server) sendResponse(resp *dns.Msg, from net.Addr, unicast bool) error {
	buf, err := resp.Pack() // 将 dns.Msg 打包为二进制
	if err != nil {
		return err
	}

	addr := from.(*net.UDPAddr)
	if addr.IP.To4() != nil {
		// IPv4 地址响应
		_, err = s.ipv4List.WriteToUDP(buf, addr)
		return err
	} else {
		// IPv6 地址响应
		_, err = s.ipv6List.WriteToUDP(buf, addr)
		return err
	}
}
