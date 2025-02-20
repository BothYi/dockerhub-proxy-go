package utils

import (
	"log"
	"net/url"
	"regexp"
)

// Logger 定义日志记录器
var Logger = log.New(log.Writer(), "[Docker-Proxy] ", log.LstdFlags|log.Lshortfile)

// IsUUID 检查字符串是否为UUID
func IsUUID(str string) bool {
	pattern := `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
	match, err := regexp.MatchString(pattern, str)
	if err != nil {
		Logger.Printf("UUID验证错误: %v", err)
		return false
	}
	return match
}

// ParseURL 解析URL并处理错误
func ParseURL(rawURL string) (*url.URL, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		Logger.Printf("URL解析错误: %v", err)
		return nil, err
	}
	return parsedURL, nil
}

// GetNginxPage 返回Nginx欢迎页面
func GetNginxPage() string {
	return `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
...` // 这里是完整的nginx页面HTML
}

// GetSearchInterface 返回搜索界面
func GetSearchInterface() string {
	return `<!DOCTYPE html>
<html>
<head>
<title>Docker Hub Search</title>
...` // 这里是完整的搜索页面HTML
}
