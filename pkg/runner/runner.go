package runner

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/g0ldencybersec/gungnir/pkg/types"
	"github.com/g0ldencybersec/gungnir/pkg/utils"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
)

var (
	logListUrl = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
	maxRetries = 3
	dnsServers = []string{
		"8.8.8.8:53",   // Google DNS
		"1.1.1.1:53",   // Cloudflare DNS
		"9.9.9.9:53",   // Quad9 DNS
	}
)

type Runner struct {
	options        *Options
	logClients     []types.CtLog
	rootDomains    map[string]bool
	rateLimitMap   map[string]time.Duration
	entryTasksChan chan types.EntryTask
	seenDomains    map[string]bool
	httpClient     *http.Client
}

func createHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Try default DNS first
			conn, err := dialer.DialContext(ctx, network, addr)
			if err == nil {
				return conn, nil
			}

			// If default DNS fails, try fallback DNS servers
			for _, dnsServer := range dnsServers {
				resolver := &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						return dialer.DialContext(ctx, network, dnsServer)
					},
				}

				addrs, err := resolver.LookupHost(ctx, strings.Split(addr, ":")[0])
				if err != nil {
					continue
				}

				if len(addrs) > 0 {
					return dialer.DialContext(ctx, network, addrs[0]+":"+strings.Split(addr, ":")[1])
				}
			}
			return nil, fmt.Errorf("all DNS resolvers failed")
		},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		TLSHandshakeTimeout: 30 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}
}

func withRetry(operation func() error) error {
	var err error
	for i := 0; i < maxRetries; i++ {
		err = operation()
		if err == nil {
			return nil
		}
		if i < maxRetries-1 {
			backoffDuration := time.Duration(1<<uint(i)) * time.Second
			time.Sleep(backoffDuration)
		}
	}
	return fmt.Errorf("operation failed after %d retries: %v", maxRetries, err)
}

func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{
		options:     options,
		rootDomains: map[string]bool{},
		seenDomains: map[string]bool{},
		httpClient:  createHTTPClient(),
	}

	// Load root domains with error handling
	if runner.options.RootList != "" {
		err := withRetry(func() error {
			return runner.loadRootDomains()
		})
		if err != nil {
			return nil, fmt.Errorf("failed to load root domains: %v", err)
		}
	}

	// Collect CT Logs with retry
	var err error
	err = withRetry(func() error {
		var loadErr error
		runner.logClients, loadErr = utils.PopulateLogs(logListUrl)
		return loadErr
	})
	if err != nil {
		return nil, fmt.Errorf("failed to populate logs after retries: %v", err)
	}

	runner.entryTasksChan = make(chan types.EntryTask, len(runner.logClients)*100)

	rateLimit := time.Duration(options.RateLimit) * time.Second
	runner.rateLimitMap = map[string]time.Duration{
		"Google":        rateLimit,
		"Sectigo":       rateLimit,
		"Let's Encrypt": rateLimit,
		"DigiCert":      rateLimit,
		"TrustAsia":     rateLimit,
	}

	return runner, nil
}

func (r *Runner) loadRootDomains() error {
	file, err := os.Open(r.options.RootList)
	if err != nil {
		return fmt.Errorf("failed to open root list file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase scanner buffer size for large files
	const maxCapacity = 1024 * 1024 // 1MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			r.rootDomains[domain] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading root list file: %v", err)
	}

	return nil
}

func (r *Runner) Run() {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	// Setup signal handling
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		fmt.Fprintf(os.Stderr, "Shutdown signal received\n")
		cancel() // Cancel the context
	}()

	// Parsing results workers
	concurrency := r.options.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.entryWorker(ctx)
		}()
	}

	// Start scanning logs
	for _, ctl := range r.logClients {
		wg.Add(1)
		go r.scanLog(ctx, ctl, &wg)
	}

	wg.Wait()
	close(r.entryTasksChan)
	fmt.Fprintf(os.Stderr, "Gracefully shutdown all routines\n")
}

func (r *Runner) entryWorker(ctx context.Context) {
	for {
		select {
		case task, ok := <-r.entryTasksChan:
			if !ok {
				return
			}
			r.processEntries(task.Entries, task.Index)
		case <-ctx.Done():
			return
		}
	}
}

func (r *Runner) scanLog(ctx context.Context, ctl types.CtLog, wg *sync.WaitGroup) {
	defer wg.Done()

	tickerDuration := time.Duration(1 * time.Second)
	for key := range r.rateLimitMap {
		if strings.Contains(ctl.Name, key) {
			tickerDuration = r.rateLimitMap[key]
			break
		}
	}

	IsGoogleLog := strings.Contains(ctl.Name, "Google")

	ticker := time.NewTicker(tickerDuration)
	defer ticker.Stop()

	var start, end int64
	var err error

	// Retry fetching the initial STH with exponential backoff
	retryBackoff := 1
	for retries := 0; retries < maxRetries; retries++ {
		if err = r.fetchAndUpdateSTH(ctx, ctl, &end); err != nil {
			if r.options.Verbose {
				fmt.Fprintf(os.Stderr, "Retry %d: Failed to get initial STH for log %s: %v\n", retries+1, ctl.Client.BaseURI(), err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(retryBackoff) * time.Second):
				retryBackoff *= 2
				continue
			}
		}
		break
	}

	start = end - 20

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if start >= end {
				if err = r.fetchAndUpdateSTH(ctx, ctl, &end); err != nil {
					if r.options.Verbose {
						fmt.Fprintf(os.Stderr, "Failed to update STH: %v\n", err)
					}
					continue
				}
				if r.options.Debug {
					if end-start > 25 {
						fmt.Fprintf(os.Stderr, "%s is behind by: %d\n", ctl.Name, end-start)
					}
				}
				continue
			}

			if IsGoogleLog {
				for start < end {
					batchEnd := start + 32
					if batchEnd > end {
						batchEnd = end
					}
					entries, err := ctl.Client.GetRawEntries(ctx, start, batchEnd)
					if err != nil {
						if r.options.Verbose {
							fmt.Fprintf(os.Stderr, "Error fetching entries for %s: %v\n", ctl.Name, err)
						}
						break
					}

					if len(entries.Entries) > 0 {
						r.entryTasksChan <- types.EntryTask{
							Entries: entries,
							Index:   start,
						}
						start += int64(len(entries.Entries))
					} else {
						break
					}
				}
			} else {
				entries, err := ctl.Client.GetRawEntries(ctx, start, end)
				if err != nil {
					if r.options.Verbose {
						fmt.Fprintf(os.Stderr, "Error fetching entries for %s: %v\n", ctl.Name, err)
					}
					continue
				}

				if len(entries.Entries) > 0 {
					r.entryTasksChan <- types.EntryTask{
						Entries: entries,
						Index:   start,
					}
					start += int64(len(entries.Entries))
				}
			}
		}
	}
}

func (r *Runner) fetchAndUpdateSTH(ctx context.Context, ctl types.CtLog, end *int64) error {
	wsth, err := ctl.Client.GetSTH(ctx)
	if err != nil {
		return err
	}
	*end = int64(wsth.TreeSize)
	return nil
}

func stripWildcard(domain string) string {
	if strings.HasPrefix(domain, "*.") {
		return domain[2:]
	}
	return domain
}

func (r *Runner) processEntries(results *ct.GetEntriesResponse, start int64) {
	index := start

	for _, entry := range results.Entries {
		index++
		rle, err := ct.RawLogEntryFromLeaf(index, &entry)
		if err != nil {
			if r.options.Verbose {
				fmt.Fprintf(os.Stderr, "Failed to parse entry %d: %v\n", index, err)
			}
			continue
		}

		switch entryType := rle.Leaf.TimestampedEntry.EntryType; entryType {
		case ct.X509LogEntryType:
			r.logCertInfo(rle)
		case ct.PrecertLogEntryType:
			r.logPrecertInfo(rle)
		default:
			if r.options.Verbose {
				fmt.Fprintf(os.Stderr, "Unknown entry type at index %d\n", index)
			}
		}
	}
}

func (r *Runner) logCertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.X509Cert == nil {
		if r.options.Verbose {
			log.Printf("Process cert at index %d: <unparsed: %v>", entry.Index, err)
		}
		return
	}

	printed := false
	if len(r.rootDomains) == 0 {
		if r.options.JsonOutput {
			utils.JsonOutput(parsedEntry.X509Cert)
		} else {
			if len(parsedEntry.X509Cert.Subject.CommonName) > 0 {
				domain := stripWildcard(parsedEntry.X509Cert.Subject.CommonName)
				if _, seen := r.seenDomains[domain]; !seen && domain != "" {
					fmt.Println(domain)
					r.seenDomains[domain] = true
					printed = true
				}
			}
			for _, domain := range parsedEntry.X509Cert.DNSNames {
				domain = stripWildcard(domain)
				if _, seen := r.seenDomains[domain]; !seen && domain != "" {
					fmt.Println(domain)
					r.seenDomains[domain] = true
					printed = true
				}
			}
		}
	} else {
		if r.options.JsonOutput {
			if utils.IsSubdomain(stripWildcard(parsedEntry.X509Cert.Subject.CommonName), r.rootDomains) {
				utils.JsonOutput(parsedEntry.X509Cert)
				return
			}
			for _, domain := range parsedEntry.X509Cert.DNSNames {
				if utils.IsSubdomain(stripWildcard(domain), r.rootDomains) {
					utils.JsonOutput(parsedEntry.X509Cert)
					break
				}
			}
		} else {
			if utils.IsSubdomain(stripWildcard(parsedEntry.X509Cert.Subject.CommonName), r.rootDomains) {
				domain := stripWildcard(parsedEntry.X509Cert.Subject.CommonName)
				if _, seen := r.seenDomains[domain]; !seen && domain != "" {
					fmt.Println(domain)
					r.seenDomains[domain] = true
					printed = true
				}
			}
			for _, domain := range parsedEntry.X509Cert.DNSNames {
				domain = stripWildcard(domain)
				if utils.IsSubdomain(stripWildcard(domain), r.rootDomains) {
					if _, seen := r.seenDomains[domain]; !seen && domain != "" {
						fmt.Println(domain)
						r.seenDomains[domain] = true
						printed = true
					}
				}
			}
		}
	}

if !printed && r.options.Verbose {
			fmt.Fprintf(os.Stderr, "No new domains found for cert at index %d\n", entry.Index)
		}
}

func (r *Runner) logPrecertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.Precert == nil {
		if r.options.Verbose {
			log.Printf("Process precert at index %d: <unparsed: %v>", entry.Index, err)
		}
		return
	}

	printed := false
	if len(r.rootDomains) == 0 {
		if r.options.JsonOutput {
			utils.JsonOutput(parsedEntry.Precert.TBSCertificate)
		} else {
			if len(parsedEntry.Precert.TBSCertificate.Subject.CommonName) > 0 {
				domain := stripWildcard(parsedEntry.Precert.TBSCertificate.Subject.CommonName)
				if _, seen := r.seenDomains[domain]; !seen && domain != "" {
					fmt.Println(domain)
					r.seenDomains[domain] = true
					printed = true
				}
			}
			for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
				domain = stripWildcard(domain)
				if _, seen := r.seenDomains[domain]; !seen && domain != "" {
					fmt.Println(domain)
					r.seenDomains[domain] = true
					printed = true
				}
			}
		}
	} else {
		if r.options.JsonOutput {
			if utils.IsSubdomain(stripWildcard(parsedEntry.Precert.TBSCertificate.Subject.CommonName), r.rootDomains) {
				utils.JsonOutput(parsedEntry.Precert.TBSCertificate)
				return
			}
			for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
				if utils.IsSubdomain(stripWildcard(domain), r.rootDomains) {
					utils.JsonOutput(parsedEntry.Precert.TBSCertificate)
					break
				}
			}
		} else {
			if utils.IsSubdomain(stripWildcard(parsedEntry.Precert.TBSCertificate.Subject.CommonName), r.rootDomains) {
				domain := stripWildcard(parsedEntry.Precert.TBSCertificate.Subject.CommonName)
				if _, seen := r.seenDomains[domain]; !seen && domain != "" {
					fmt.Println(domain)
					r.seenDomains[domain] = true
					printed = true
				}
			}
			for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
				domain = stripWildcard(domain)
				if utils.IsSubdomain(stripWildcard(domain), r.rootDomains) {
					if _, seen := r.seenDomains[domain]; !seen && domain != "" {
						fmt.Println(domain)
						r.seenDomains[domain] = true
						printed = true
					}
				}
			}
		}
	}

	if !printed && r.options.Verbose {
		fmt.Fprintf(os.Stderr, "No new domains found for precert at index %d\n", entry.Index)
	}
}
//
//// Options holds the configuration for the Runner
//type Options struct {
//	RootList    string
//	Concurrency int
//	RateLimit   int
//	JsonOutput  bool
//	Verbose     bool
//	Debug       bool
//}
