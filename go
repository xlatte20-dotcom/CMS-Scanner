package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/twmb/murmur3"
)

type Feature struct {
	Pattern string `json:"pattern"`
	Weight  int    `json:"weight"`
}

type CMSConfig struct {
	Name          string    `json:"name"`
	FileName      string    `json:"file_name"`
	MinScore      int       `json:"min_score"`
	Features      []Feature `json:"features"`
	Headers       []Feature `json:"headers"`
	FaviconHashes []string  `json:"favicon_hashes"`
	APIPaths      []string  `json:"api_paths"`
	APIKeywords   []string  `json:"api_keywords"`
}

type ScanResult struct {
	URL      string
	CMSName  string
	FileName string
}

var (
	outputDir = "output"
	fileMutex sync.Mutex
)

func main() {
	configs, err := loadConfigs("config.json")
	if err != nil {
		fmt.Printf("[-] 读取 config.json 失败: %v\n", err)
		return
	}
	fmt.Printf("[+] 成功加载 %d 条 CMS 指纹规则！\n", len(configs))

	targets, err := readTargets("targets.txt")
	if err != nil {
		fmt.Printf("[-] 读取 targets.txt 失败: %v\n", err)
		return
	}

	_ = os.MkdirAll(outputDir, 0755)

	client := &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	tasks := make(chan string, len(targets))
	results := make(chan ScanResult, len(targets))

	var wg sync.WaitGroup
	concurrency := 10

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range tasks {
				res := scanTarget(target, configs, client)
				results <- res
			}
		}()
	}

	for _, target := range targets {
		tasks <- target
	}
	close(tasks)

	go func() {
		wg.Wait()
		close(results)
	}()

	for res := range results {
		fmt.Printf("[+] %-28s => %-18s | 存入文件: %s/%s\n", res.URL, res.CMSName, outputDir, res.FileName)
		saveResult(res)
	}

	fmt.Println("\n[√] 扫描完成！所有识别结果已分类存入 output/ 目录下的对应 TXT 文件中。")
}

func scanTarget(target string, configs []CMSConfig, client *http.Client) ScanResult {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return ScanResult{URL: target, CMSName: "无法连接", FileName: "Error.txt"}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

	resp, err := client.Do(req)
	if err != nil {
		return ScanResult{URL: target, CMSName: "无法连接", FileName: "Error.txt"}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	htmlContent := strings.ToLower(string(bodyBytes))

	var headersBuilder strings.Builder
	for k, v := range resp.Header {
		headersBuilder.WriteString(fmt.Sprintf("%s: %s\n", strings.ToLower(k), strings.ToLower(strings.Join(v, "; "))))
	}
	headerContent := headersBuilder.String()

	// 阶段 1: 首页特征计分
	for _, cms := range configs {
		score := 0
		for _, f := range cms.Features {
			if strings.Contains(htmlContent, strings.ToLower(f.Pattern)) {
				score += f.Weight
			}
		}
		for _, h := range cms.Headers {
			if strings.Contains(headerContent, strings.ToLower(h.Pattern)) {
				score += h.Weight
			}
		}
		if score >= cms.MinScore {
			return ScanResult{URL: target, CMSName: cms.Name, FileName: cms.FileName}
		}
	}

	// 阶段 2: Favicon 图标验证
	iconHash := getFaviconHash(target, client)
	if iconHash != "" {
		for _, cms := range configs {
			for _, hash := range cms.FaviconHashes {
				if hash == iconHash {
					return ScanResult{URL: target, CMSName: cms.Name, FileName: cms.FileName}
				}
			}
		}
	}

	// 阶段 3: 专属 API 探测
	for _, cms := range configs {
		for _, apiPath := range cms.APIPaths {
			apiURL := strings.TrimRight(target, "/") + apiPath
			apiReq, _ := http.NewRequest("GET", apiURL, nil)
			apiReq.Header.Set("User-Agent", "Mozilla/5.0")
			apiResp, err := client.Do(apiReq)
			if err == nil && apiResp.StatusCode == 200 {
				apiBodyBytes, _ := io.ReadAll(apiResp.Body)
				apiResp.Body.Close()
				apiBody := strings.ToLower(string(apiBodyBytes))
				for _, kw := range cms.APIKeywords {
					if strings.Contains(apiBody, strings.ToLower(kw)) {
						return ScanResult{URL: target, CMSName: cms.Name, FileName: cms.FileName}
					}
				}
			}
		}
	}

	return ScanResult{URL: target, CMSName: "未知 CMS", FileName: "Unknown.txt"}
}

func getFaviconHash(target string, client *http.Client) string {
	iconURL := strings.TrimRight(target, "/") + "/favicon.ico"
	req, _ := http.NewRequest("GET", iconURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil || len(body) == 0 {
		return ""
	}

	b64 := base64.StdEncoding.EncodeToString(body)
	var buffer bytes.Buffer
	for i, ch := range b64 {
		buffer.WriteRune(ch)
		if (i+1)%76 == 0 {
			buffer.WriteString("\n")
		}
	}
	buffer.WriteString("\n")

	h32 := murmur3.New32()
	h32.Write(buffer.Bytes())
	return fmt.Sprintf("%d", int32(h32.Sum32()))
}

func loadConfigs(filePath string) ([]CMSConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var configs []CMSConfig
	err = json.Unmarshal(data, &configs)
	return configs, err
}

func readTargets(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	return targets, scanner.Err()
}

func saveResult(res ScanResult) {
	fileMutex.Lock()
	defer fileMutex.Unlock()

	filePath := filepath.Join(outputDir, res.FileName)
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	f.WriteString(res.URL + "\n")
}
