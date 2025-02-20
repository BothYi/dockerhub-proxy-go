package main

import (
	"flag"
	"fmt"
	"net/http"

	"docker-proxy/config"
	"docker-proxy/proxy"
	"docker-proxy/utils"
)

func main() {
	// 命令行参数
	port := flag.Int("port", 8443, "服务监听端口")
	flag.Parse()

	// 初始化配置
	cfg := config.NewConfig()

	// 初始化代理
	proxy := proxy.NewProxy(cfg)

	// 设置路由
	http.HandleFunc("/", proxy.ProxyRequest)

	// 启动服务
	addr := fmt.Sprintf(":%d", *port)
	utils.Logger.Printf("Docker Registry代理服务启动在 http://0.0.0.0%s", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		utils.Logger.Fatalf("服务启动失败: %v", err)
	}
}
