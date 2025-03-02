package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"net/http"
	"crypto/tls"
	"strconv"

	"gopkg.in/yaml.v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Endpoint struct {
	IP         string `yaml:"ip"`
	PORT       int    `yaml:"port"`
	HOST_HEADER string `yaml:"host_header"`
	HCPath     string `yaml:"hc_path"`
	IsHealthy  bool   `yaml:"is_healthy"`
	IsHTTPS    bool   `yaml:"is_https"`  // 追加: HTTPS ヘルスチェック対応
}

var healthStatus = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "endpoint_health_status",
		Help: "Health status of endpoints (1 = healthy, 0 = unhealthy)",
	},
	[]string{"ip", "port", "host_header", "hc_path"},
)

func init() {
	// Register the metric
	prometheus.MustRegister(healthStatus)
}

// GSLB_Domain: 監視対象のドメイン情報
type GSLB_Domain struct {
	DomainName     string     `yaml:"domain_name"`
	UUID           string     `yaml:"uuid"`
	Endpoints      []Endpoint `yaml:"endpoints"`
	HCIntervalSec  int        `yaml:"hc_interval_sec"`
	TimeoutSec     int        `yaml:"timeout_sec"`
	Password       string     `yaml:"password"`
	TTL            int        `yaml:"ttl"`
}

// Prober: GSLB の監視を行う
type Prober struct {
	CurrentSerial int64          `yaml:"current_serial"`
	GSLB_Domains  []GSLB_Domain  `yaml:"gslb_domains"`
	mu            sync.Mutex
}

// Update the Prometheus metric
func (p *Prober) updateMetrics() {
	for {
		time.Sleep(1 * time.Second)
		for _, domain := range p.GSLB_Domains {
			for _, ep := range domain.Endpoints {
				value := 0.0
				if ep.IsHealthy {
					value = 1.0
				}
				healthStatus.WithLabelValues(ep.IP, strconv.Itoa(ep.PORT), ep.HOST_HEADER, ep.HCPath).Set(value)
			}
		}
	}
}

// YAML 設定ファイルのパス
const configFile = "gslb_config.yml"

// 設定ファイルを読み込む
func (p *Prober) LoadConfig() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		fmt.Println("設定ファイルが見つかりません。新規作成します。")
		return nil // ファイルがない場合は初期状態で起動
	}

	err = yaml.Unmarshal(data, p)
	if err != nil {
		fmt.Println("設定ファイルの読み込みに失敗:", err)
		return err
	}

	fmt.Println("設定ファイルをロードしました。")
	return nil
}

// ✅ 設定を YAML に保存する
func (p *Prober) SaveConfig() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	data, err := yaml.Marshal(p)
	if err != nil {
		fmt.Println("🚨 設定ファイルのシリアライズに失敗:", err)
		return err
	}

	err = ioutil.WriteFile(configFile, data, 0644)
	if err != nil {
		fmt.Println("設定ファイルの書き込みに失敗:", err)
		return err
	}

	fmt.Println("設定をファイルに保存しました。")
	return nil
}

// ドメインを追加
func (p *Prober) AddNewDomain(g GSLB_Domain) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.GSLB_Domains = append(p.GSLB_Domains, g)
}

// ドメインを削除
func (p *Prober) DeleteDomainByName(pass string, domainName string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, v := range p.GSLB_Domains {
		if v.DomainName == domainName && v.Password == pass {
			p.GSLB_Domains = append(p.GSLB_Domains[:i], p.GSLB_Domains[i+1:]...)
			fmt.Println("Deleted domain:", domainName)
			return
		}
	}
}

// Graceful Shutdown（Ctrl + C で終了時に設定を保存）
func (p *Prober) SetupGracefulShutdown() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		fmt.Println("\n🛑 Graceful Shutdown 開始... 設定を保存します。")
		p.SaveConfig()
		fmt.Println("✅ シャットダウン完了。")
		os.Exit(0)
	}()
}

// 毎秒ヘルスチェックを実行
func (p *Prober) Probe() {
	for {
		time.Sleep(1 * time.Second)
		p.mu.Lock()
		for i, domain := range p.GSLB_Domains {
			if time.Now().Unix()%int64(domain.HCIntervalSec) == 0 {
				go p.ProbeDomain(i)
			}
		}
		p.mu.Unlock()
	}
}

// 各エンドポイントのヘルスチェックを実行
func (p *Prober) ProbeDomain(domainIndex int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	domain := &p.GSLB_Domains[domainIndex]

	for i, ep := range domain.Endpoints {
		scheme := "http"
		if ep.IsHTTPS {
			scheme = "https"
		}

		url := fmt.Sprintf("%s://%s:%d%s", scheme, ep.IP, ep.PORT, ep.HCPath)

		// HTTP クライアントを作成（HTTPS の場合は証明書の検証を無効化）
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: ep.IsHTTPS}, // 🔥 証明書の検証をスキップ
		}
		client := http.Client{
			Timeout:   time.Duration(domain.TimeoutSec) * time.Second,
			Transport: tr,
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Printf("🚨 [ERROR] Failed to create request for %s: %v\n", url, err)
			domain.Endpoints[i].IsHealthy = false
			continue
		}

		// Host ヘッダーが設定されている場合は追加
		if ep.HOST_HEADER != "" {
			req.Host = ep.HOST_HEADER
		}

		// 送信するリクエストの詳細をログに出力
		fmt.Printf("🔎 [DEBUG] Sending HC request: %s (Host: %s)\n", url, req.Host)

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("❌ [ERROR] Health check request failed for %s [%s]: %v\n", domain.DomainName, ep.IP, err)
			domain.Endpoints[i].IsHealthy = false
			continue
		}
		defer resp.Body.Close()

		// HTTP ステータスコードが 200 でない場合、詳細を出力
		if resp.StatusCode != 200 {
			body, _ := ioutil.ReadAll(resp.Body) // レスポンスの内容も取得
			fmt.Printf("[ERROR] Health check failed: %s [%s] Status %d\nResponse: %s\n", domain.DomainName, ep.IP, resp.StatusCode, string(body))
			domain.Endpoints[i].IsHealthy = false
			continue
		}

		fmt.Printf("[SUCCESS] Healthy: %s [%s] Status %d\n", domain.DomainName, ep.IP, resp.StatusCode)
		domain.Endpoints[i].IsHealthy = true
	}
}



// ゾーンファイルを更新
func (p *Prober) UpdateZoneFile() {
	for {
		time.Sleep(1 * time.Second)

		p.mu.Lock()
		var zoneData strings.Builder

		// ゾーンファイルのヘッダー部分を定義
		zoneData.WriteString("$ORIGIN workers-bub.com.\n")
		zoneData.WriteString("$TTL 30\n")
		zoneData.WriteString(fmt.Sprintf("@   IN  SOA ns02.workers-bub.com. ns01.workers-bub.com. (\n"+
			"                %d ; Serial\n"+
			"                7200       ; Refresh\n"+
			"                3600       ; Retry\n"+
			"                1209600    ; Expire\n"+
			"                30 )       ; Minimum TTL\n\n", p.CurrentSerial))

		// NS レコードを追加
		zoneData.WriteString("@   IN  NS  ns01.workers-bub.com.\n")
		zoneData.WriteString("@   IN  NS  ns02.workers-bub.com.\n\n")

		zoneData.WriteString("ns02 86400 IN A 162.43.53.234\n")

		// A レコードの追加
		for _, domain := range p.GSLB_Domains {
			for _, ep := range domain.Endpoints {
				if ep.IsHealthy {
					zoneData.WriteString(fmt.Sprintf("%s %d IN A %s\n", domain.DomainName, domain.TTL, ep.IP))
				}
			}
		}

		// ゾーンファイルを更新
		err := ioutil.WriteFile("/etc/coredns/zones/workers-bub.com.zone", []byte(zoneData.String()), 0644)
		if err != nil {
			fmt.Println("Failed to update zone file:", err)
		} else {
			fmt.Println("Updated zone file")
		}

		p.CurrentSerial++
		p.mu.Unlock()
	}
}


// API ハンドラー (ドメイン追加)
func (p *Prober) HandleDomainAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var domain GSLB_Domain
	if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	p.AddNewDomain(domain)
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Domain added")
}

// API ハンドラー (ドメイン削除)
func (p *Prober) HandleDomainDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	pass := query.Get("password")
	domainName := query.Get("domain")

	if pass == "" || domainName == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}

	p.DeleteDomainByName(pass, domainName)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Domain deleted")
}

// API ハンドラー (ドメインリスト取得)
func (p *Prober) HandleDomainList(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p.GSLB_Domains)
}

func main() {
	prober := &Prober{
		CurrentSerial: 2024022801,
		GSLB_Domains:  []GSLB_Domain{},
	}

	// 設定ファイルからロード
	prober.LoadConfig()

	// Graceful Shutdown を設定
	prober.SetupGracefulShutdown()

	// HTTP ハンドラを設定
	http.Handle("/metrics", promhttp.Handler())

	// API ハンドラ登録
	http.HandleFunc("/v1/domain/add", prober.HandleDomainAdd)
	http.HandleFunc("/v1/domain/delete", prober.HandleDomainDelete)
	http.HandleFunc("/v1/domain/list", prober.HandleDomainList)

	// 並行処理でプローバーを実行
	go prober.Probe()
	go prober.UpdateZoneFile()
	go prober.updateMetrics();

	fmt.Println("Starting GSLB Prober server on :8080...")
	// http.ListenAndServe(":8080", nil)

	err := http.ListenAndServe(":8089", nil)
	if err != nil {
		fmt.Println("🚨 HTTP Server Error:", err)
		if strings.Contains(err.Error(), "address already in use") {
			fmt.Println("ポート 8080 が既に使用されています。他のプロセスが動いていないか確認してください。")
		}
		os.Exit(1) // サーバーが起動できない場合は強制終了
	}
}

