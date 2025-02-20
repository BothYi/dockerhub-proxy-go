package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"docker-proxy/config"
	"docker-proxy/utils"
)

type Proxy struct {
	config *config.Config
	client *http.Client
}

func NewProxy(cfg *config.Config) *Proxy {
	return &Proxy{
		config: cfg,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				DisableKeepAlives:     false,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (p *Proxy) ProxyRequest(w http.ResponseWriter, r *http.Request) {
	// 打印详细的请求信息
	utils.Logger.Printf("收到请求: %s %s", r.Method, r.URL.String())
	utils.Logger.Printf("请求头: %+v", r.Header)
	utils.Logger.Printf("原始Host: %s", r.Host)

	// 获取原始请求的 scheme
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	utils.Logger.Printf("原始Scheme: %s", scheme)

	upstream := p.config.GetUpstream(r.Host)
	utils.Logger.Printf("匹配到的上游服务器: %s", upstream)

	if upstream == "" {
		utils.Logger.Printf("未找到匹配的上游服务器，可用路由: %v", p.config.Routes)
		p.responseNotFound(w)
		return
	}

	isDockerHub := p.config.IsDockerHub(upstream)
	authorization := r.Header.Get("Authorization")

	// 处理 /v2/ 请求
	if r.URL.Path == "/v2/" {
		p.handleV2Request(w, r, upstream, authorization, scheme)
		return
	}

	// 处理认证请求
	if r.URL.Path == "/v2/auth" {
		p.handleAuthRequest(w, r, upstream, authorization, isDockerHub)
		return
	}

	// 处理 DockerHub 官方镜像重定向
	if isDockerHub {
		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) == 5 {
			pathParts = append(pathParts[:2], append([]string{"library"}, pathParts[2:]...)...)
			redirectURL := fmt.Sprintf("https://%s%s", r.Host, strings.Join(pathParts, "/"))
			if r.URL.RawQuery != "" {
				redirectURL += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
			return
		}
	}

	// 转发请求
	resp, err := p.forwardRequest(r, upstream, isDockerHub)
	if err != nil {
		utils.Logger.Printf("请求转发错误: %v", err)
		http.Error(w, "代理请求失败", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		p.responseUnauthorized(w, r.Host, scheme)
		return
	}

	// 处理 DockerHub blob 重定向
	if isDockerHub && resp.StatusCode == http.StatusTemporaryRedirect {
		location := resp.Header.Get("Location")
		if location != "" {
			redirectResp, err := p.client.Get(location)
			if err != nil {
				http.Error(w, "重定向请求失败", http.StatusBadGateway)
				return
			}
			defer redirectResp.Body.Close()
			p.copyResponse(w, redirectResp)
			return
		}
	}

	p.copyResponse(w, resp)
}

func (p *Proxy) handleV2Request(w http.ResponseWriter, r *http.Request, upstream, authorization string, scheme string) {
	utils.Logger.Printf("处理 v2 请求开始: %s", upstream+"/v2/")
	newURL := upstream + "/v2/"

	req, err := http.NewRequest("GET", newURL, nil)
	if err != nil {
		utils.Logger.Printf("创建v2请求失败: %v", err)
		http.Error(w, "创建请求失败", http.StatusInternalServerError)
		return
	}

	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.Header.Set("Host", strings.TrimPrefix(upstream, "https://"))
	utils.Logger.Printf("v2请求头: %+v", req.Header)

	utils.Logger.Printf("开始发送v2请求...")
	resp, err := p.client.Do(req)
	if err != nil {
		utils.Logger.Printf("v2请求失败: %v", err)
		if strings.Contains(err.Error(), "timeout") {
			utils.Logger.Printf("v2请求超时")
		} else if strings.Contains(err.Error(), "connection") {
			utils.Logger.Printf("v2请求连接错误")
		}
		http.Error(w, "代理请求失败", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	utils.Logger.Printf("v2响应状态: %d", resp.StatusCode)
	utils.Logger.Printf("v2响应头: %+v", resp.Header)

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		utils.Logger.Printf("读取v2响应体失败: %v", err)
		http.Error(w, "读取响应失败", http.StatusInternalServerError)
		return
	}
	utils.Logger.Printf("v2响应体: %s", string(body))

	if resp.StatusCode == http.StatusUnauthorized {
		utils.Logger.Printf("需要认证，返回认证响应")
		p.responseUnauthorized(w, r.Host, scheme)
		return
	}

	// 重新设置响应体
	resp.Body = io.NopCloser(bytes.NewBuffer(body))
	p.copyResponse(w, resp)
}

func (p *Proxy) handleAuthRequest(w http.ResponseWriter, r *http.Request, upstream, authorization string, isDockerHub bool) {
	utils.Logger.Printf("处理认证请求: %s", r.URL.String())
	utils.Logger.Printf("Authorization: %s", authorization)
	// 获取认证信息
	newURL := upstream + "/v2/"
	resp, err := p.client.Get(newURL)
	if err != nil {
		http.Error(w, "认证请求失败", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		p.copyResponse(w, resp)
		return
	}

	authenticate := resp.Header.Get("Www-Authenticate")
	if authenticate == "" {
		p.copyResponse(w, resp)
		return
	}

	wwwAuthenticate := p.parseAuthenticate(authenticate)
	scope := r.URL.Query().Get("scope")

	// 处理 DockerHub 官方镜像的 scope
	if scope != "" && isDockerHub {
		scopeParts := strings.Split(scope, ":")
		if len(scopeParts) == 3 && !strings.Contains(scopeParts[1], "/") {
			scopeParts[1] = "library/" + scopeParts[1]
			scope = strings.Join(scopeParts, ":")
		}
	}

	tokenResp, err := p.fetchToken(wwwAuthenticate, scope, authorization)
	if err != nil {
		http.Error(w, "获取token失败", http.StatusBadGateway)
		return
	}
	defer tokenResp.Body.Close()

	p.copyResponse(w, tokenResp)
}

type WwwAuthenticate struct {
	Realm   string
	Service string
}

func (p *Proxy) parseAuthenticate(authenticateStr string) WwwAuthenticate {
	// 修改正则表达式，匹配 key="value" 模式
	re := regexp.MustCompile(`(\w+)="([^"]*)"`)
	matches := re.FindAllStringSubmatch(authenticateStr, -1)

	auth := WwwAuthenticate{}
	for _, match := range matches {
		if len(match) == 3 { // 完整匹配包括 key 和 value
			key := match[1]
			value := match[2]
			switch key {
			case "realm":
				auth.Realm = value
			case "service":
				auth.Service = value
			}
		}
	}

	utils.Logger.Printf("解析认证头: %s => realm=%s, service=%s",
		authenticateStr, auth.Realm, auth.Service)

	if auth.Realm == "" || auth.Service == "" {
		utils.Logger.Printf("警告: 认证头解析不完整: %v", auth)
	}

	return auth
}

func (p *Proxy) fetchToken(auth WwwAuthenticate, scope, authorization string) (*http.Response, error) {
	tokenURL := auth.Realm
	if auth.Service != "" {
		tokenURL += "?service=" + auth.Service
	}
	if scope != "" {
		if strings.Contains(tokenURL, "?") {
			tokenURL += "&scope=" + scope
		} else {
			tokenURL += "?scope=" + scope
		}
	}

	req, err := http.NewRequest("GET", tokenURL, nil)
	if err != nil {
		return nil, err
	}

	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}

	return p.client.Do(req)
}

func (p *Proxy) forwardRequest(r *http.Request, upstream string, isDockerHub bool) (*http.Response, error) {
	newURL := upstream + r.URL.Path
	if r.URL.RawQuery != "" {
		newURL += "?" + r.URL.RawQuery
	}
	utils.Logger.Printf("转发请求到: %s", newURL)

	req, err := http.NewRequest(r.Method, newURL, r.Body)
	if err != nil {
		utils.Logger.Printf("创建请求失败: %v", err)
		return nil, err
	}

	req.Header = r.Header.Clone()
	req.Header.Set("Host", strings.TrimPrefix(upstream, "https://"))
	utils.Logger.Printf("转发请求头: %+v", req.Header)

	resp, err := p.client.Do(req)
	if err != nil {
		utils.Logger.Printf("发送请求失败: %v", err)
		return nil, err
	}

	utils.Logger.Printf("收到响应: Status=%d", resp.StatusCode)
	utils.Logger.Printf("响应头: %+v", resp.Header)
	return resp, nil
}

func (p *Proxy) copyResponse(w http.ResponseWriter, resp *http.Response) {
	utils.Logger.Printf("复制响应: Status=%d", resp.StatusCode)
	utils.Logger.Printf("响应头: %+v", resp.Header)

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	written, err := io.Copy(w, resp.Body)
	if err != nil {
		utils.Logger.Printf("复制响应体错误: %v", err)
	} else {
		utils.Logger.Printf("成功写入响应体: %d bytes", written)
	}
}

func (p *Proxy) responseUnauthorized(w http.ResponseWriter, host string, scheme string) {

	authHeader := fmt.Sprintf(
		`Bearer realm="%s://%s/v2/auth",service="cloudflare-docker-proxy"`,
		scheme, host,
	)
	utils.Logger.Printf("设置认证头: %s", authHeader)

	w.Header().Set("Www-Authenticate", authHeader)
	w.WriteHeader(http.StatusUnauthorized)

	response := map[string]string{"message": "UNAUTHORIZED"}
	utils.Logger.Printf("返回未授权响应: %+v", response)
	json.NewEncoder(w).Encode(response)
}

func (p *Proxy) responseNotFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"routes": p.config.Routes,
	})
}
