package mdns

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns" // 使用 miekg 的 DNS 库处理 DNS 请求
)

const (
	// 默认 TTL（Time To Live）设置为 120 秒
	defaultTTL = 120
)

// Zone 接口定义了一个区域（Zone），用于动态响应 DNS 查询
type Zone interface {
	// Records 返回匹配 DNS 查询问题的 DNS 记录
	Records(q dns.Question) []dns.RR
}

// MDNSService 表示一个通过 mDNS 发布的服务，实现了 Zone 接口
type MDNSService struct {
	Instance string   // 实例名，例如 "MyPrinter"
	Service  string   // 服务名，例如 "_http._tcp."
	Domain   string   // 域名，默认是 "local"
	HostName string   // 主机名，例如 "mymachine.local."
	Port     int      // 服务端口
	IPs      []net.IP // 绑定服务的 IP 地址
	TXT      []string // 附加信息（TXT记录）

	// 内部构建好的地址字段
	serviceAddr  string // 完整服务地址，例如 "_http._tcp.local."
	instanceAddr string // 实例地址，例如 "MyPrinter._http._tcp.local."
	enumAddr     string // 服务枚举地址 "_services._dns-sd._udp.local."
}

// validateFQDN 校验是否是一个合法的 FQDN（以点号结尾）
func validateFQDN(s string) error {
	if len(s) == 0 {
		return fmt.Errorf("FQDN 不能为空")
	}
	if s[len(s)-1] != '.' {
		return fmt.Errorf("FQDN 必须以点号结尾: %s", s)
	}
	return nil
}

// NewMDNSService 创建一个新的 MDNSService 实例
// 如果未指定 domain、hostName 或 IP，会自动从系统推断默认值
func NewMDNSService(instance, service, domain, hostName string, port int, ips []net.IP, txt []string) (*MDNSService, error) {
	// 参数合法性检查
	if instance == "" {
		return nil, fmt.Errorf("缺少服务实例名")
	}
	if service == "" {
		return nil, fmt.Errorf("缺少服务名")
	}
	if port == 0 {
		return nil, fmt.Errorf("缺少服务端口")
	}

	// 默认 domain 设置为 local.
	if domain == "" {
		domain = "local."
	}
	if err := validateFQDN(domain); err != nil {
		return nil, fmt.Errorf("域名 %q 不是合法的 FQDN: %v", domain, err)
	}

	// 若未指定主机名，尝试使用当前主机名
	if hostName == "" {
		var err error
		hostName, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("无法获取主机名: %v", err)
		}
		// 添加点号形成 FQDN
		hostName = fmt.Sprintf("%s.", hostName)
	}
	if err := validateFQDN(hostName); err != nil {
		return nil, fmt.Errorf("主机名 %q 不是合法的 FQDN: %v", hostName, err)
	}

	// 若未指定 IP，尝试通过主机名查询 IP 地址
	if len(ips) == 0 {
		var err error
		ips, err = net.LookupIP(hostName)
		if err != nil {
			// 有些系统需要主机名加 domain 才能查询成功
			tmpHostName := fmt.Sprintf("%s%s", hostName, domain)
			ips, err = net.LookupIP(tmpHostName)
			if err != nil {
				return nil, fmt.Errorf("无法获取主机 %s 的 IP 地址", hostName)
			}
		}
	}

	// 校验 IP 是否是有效的 IPv4 或 IPv6 地址
	for _, ip := range ips {
		if ip.To4() == nil && ip.To16() == nil {
			return nil, fmt.Errorf("无效的 IP 地址: %v", ip)
		}
	}

	// 返回构建好的服务实例
	return &MDNSService{
		Instance:     instance,
		Service:      service,
		Domain:       domain,
		HostName:     hostName,
		Port:         port,
		IPs:          ips,
		TXT:          txt,
		serviceAddr:  fmt.Sprintf("%s.%s.", trimDot(service), trimDot(domain)),
		instanceAddr: fmt.Sprintf("%s.%s.%s.", instance, trimDot(service), trimDot(domain)),
		enumAddr:     fmt.Sprintf("_services._dns-sd._udp.%s.", trimDot(domain)),
	}, nil
}

// trimDot 去除字符串首尾的点号
func trimDot(s string) string {
	return strings.Trim(s, ".")
}

// Records 根据 DNS 查询问题返回相应记录
func (m *MDNSService) Records(q dns.Question) []dns.RR {
	switch q.Name {
	case m.enumAddr:
		return m.serviceEnum(q) // 枚举服务类型
	case m.serviceAddr:
		return m.serviceRecords(q) // 匹配服务名
	case m.instanceAddr:
		return m.instanceRecords(q) // 匹配具体服务实例
	case m.HostName:
		// 若查询的是主机名的 A/AAAA 类型记录
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			return m.instanceRecords(q)
		}
		fallthrough
	default:
		return nil
	}
}

// 构建服务类型枚举响应（_services._dns-sd._udp.local）
func (m *MDNSService) serviceEnum(q dns.Question) []dns.RR {
	switch q.Qtype {
	case dns.TypeANY, dns.TypePTR:
		rr := &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Ptr: m.serviceAddr,
		}
		return []dns.RR{rr}
	default:
		return nil
	}
}

// 构建服务名的响应（_http._tcp.local）
func (m *MDNSService) serviceRecords(q dns.Question) []dns.RR {
	switch q.Qtype {
	case dns.TypeANY, dns.TypePTR:
		// 返回 PTR 指向具体服务实例
		rr := &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Ptr: m.instanceAddr,
		}
		// 获取实例的其他记录（SRV, A, AAAA, TXT）
		instRecs := m.instanceRecords(dns.Question{
			Name:  m.instanceAddr,
			Qtype: dns.TypeANY,
		})
		return append([]dns.RR{rr}, instRecs...)
	default:
		return nil
	}
}

// 构建服务实例名的响应（如 MyPrinter._http._tcp.local.）
func (m *MDNSService) instanceRecords(q dns.Question) []dns.RR {
	switch q.Qtype {
	case dns.TypeANY:
		// 返回 SRV、TXT、A、AAAA
		recs := m.instanceRecords(dns.Question{Name: m.instanceAddr, Qtype: dns.TypeSRV})
		recs = append(recs, m.instanceRecords(dns.Question{Name: m.instanceAddr, Qtype: dns.TypeTXT})...)
		return recs

	case dns.TypeA:
		var rr []dns.RR
		for _, ip := range m.IPs {
			if ip4 := ip.To4(); ip4 != nil {
				rr = append(rr, &dns.A{
					Hdr: dns.RR_Header{
						Name:   m.HostName,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    defaultTTL,
					},
					A: ip4,
				})
			}
		}
		return rr

	case dns.TypeAAAA:
		var rr []dns.RR
		for _, ip := range m.IPs {
			if ip.To4() != nil {
				// IPv4 忽略 AAAA 响应（可按需配置为转换）
				continue
			}
			if ip16 := ip.To16(); ip16 != nil {
				rr = append(rr, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   m.HostName,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    defaultTTL,
					},
					AAAA: ip16,
				})
			}
		}
		return rr

	case dns.TypeSRV:
		// 返回 SRV 记录，指明服务端口和主机
		srv := &dns.SRV{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeSRV,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Priority: 10,
			Weight:   1,
			Port:     uint16(m.Port),
			Target:   m.HostName,
		}
		recs := []dns.RR{srv}
		// 加上 A 和 AAAA 记录
		recs = append(recs, m.instanceRecords(dns.Question{Name: m.instanceAddr, Qtype: dns.TypeA})...)
		recs = append(recs, m.instanceRecords(dns.Question{Name: m.instanceAddr, Qtype: dns.TypeAAAA})...)
		return recs

	case dns.TypeTXT:
		// 返回 TXT 记录（附加信息）
		txt := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Txt: m.TXT,
		}
		return []dns.RR{txt}
	}
	return nil
}
