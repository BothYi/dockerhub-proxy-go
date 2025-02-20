package config

import (
	"docker-proxy/utils"
	"strings"
)

type Config struct {
	// Docker镜像仓库主机地址
	HubHost string
	// Docker认证服务器地址
	AuthURL string
	// 自定义的工作服务器地址
	WorkersURL string
	// 屏蔽的爬虫UA
	BlockedCrawlers []string
	// 路由表
	Routes map[string]string
	// 自定义的域名
	CustomDomain string
	// 调试模式
	Debug bool
}

func NewConfig() *Config {
	customDomain := "bothyi.cn"
	dockerHub := "https://registry-1.docker.io"

	routes := map[string]string{
		"docker." + customDomain:         dockerHub,
		"quay." + customDomain:           "https://quay.io",
		"gcr." + customDomain:            "https://gcr.io",
		"k8s-gcr." + customDomain:        "https://k8s.gcr.io",
		"k8s." + customDomain:            "https://registry.k8s.io",
		"ghcr." + customDomain:           "https://ghcr.io",
		"cloudsmith." + customDomain:     "https://docker.cloudsmith.io",
		"ecr." + customDomain:            "https://public.ecr.aws",
		"docker-staging." + customDomain: dockerHub,
	}

	return &Config{
		HubHost:      "registry-1.docker.io",
		AuthURL:      "https://auth.docker.io",
		WorkersURL:   "",
		Routes:       routes,
		CustomDomain: customDomain,
		Debug:        false,
	}
}

// RouteByHost 根据主机名选择对应的上游地址
func (c *Config) RouteByHost(host string) (string, bool) {
	if upstream, ok := c.Routes[host]; ok {
		return upstream, false
	}
	return c.HubHost, true
}

// AddBlockedCrawlers 添加需要屏蔽的爬虫UA
func (c *Config) AddBlockedCrawlers(crawlers string) {
	// 清理输入字符串
	cleaned := strings.NewReplacer(" ", ",", "\t", ",", "\n", ",", "\r", ",", "\"", "", "'", "").Replace(crawlers)
	// 分割字符串
	newCrawlers := strings.Split(cleaned, ",")
	// 过滤空字符串
	for _, crawler := range newCrawlers {
		if crawler != "" {
			c.BlockedCrawlers = append(c.BlockedCrawlers, crawler)
		}
	}
}

func (c *Config) GetUpstream(host string) string {
	// 移除端口号
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}
	utils.Logger.Printf("处理后的host: %s", host) // 添加日志

	if upstream, ok := c.Routes[host]; ok {
		return upstream
	}
	if c.Debug {
		return "https://registry-1.docker.io"
	}
	return ""
}

func (c *Config) IsDockerHub(upstream string) bool {
	return upstream == "https://registry-1.docker.io"
}
