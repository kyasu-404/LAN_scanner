package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
)

const DefaultThreads = 100

// ================== NMAP XML ==================

type NmapRun struct {
	Hosts []NmapHost `xml:"host"`
}

type NmapHost struct {
	Status    NmapStatus     `xml:"status"`
	Addresses []NmapAddress  `xml:"address"`
	Hostnames []NmapHostname `xml:"hostnames>hostname"`
	Ports     []NmapPort     `xml:"ports>port"`
	Os        NmapOs         `xml:"os"`
}

type NmapStatus struct {
	State string `xml:"state,attr"`
}

type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type NmapHostname struct {
	Name string `xml:"name,attr"`
}

type NmapPort struct {
	PortId  int         `xml:"portid,attr"`
	State   NmapState   `xml:"state"`
	Service NmapService `xml:"service"`
}

type NmapState struct {
	State string `xml:"state,attr"`
}

type NmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

type NmapOs struct {
	OsMatches []NmapOsMatch `xml:"osmatch"`
}

type NmapOsMatch struct {
	Name string `xml:"name,attr"`
}

// ================== RESULT STRUCTS ==================

type PortInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Product string `json:"product"`
	Version string `json:"version"`
}

type ScanResult struct {
	IP         string     `json:"ip"`
	Hostname   string     `json:"hostname"`
	OS         string     `json:"os"`
	MAC        string     `json:"mac"`
	Vendor     string     `json:"vendor"`
	Ports      []PortInfo `json:"ports"`
	DeviceType string     `json:"device_type"`
	Confidence int        `json:"confidence"`
}

// ================== INPUT HELPERS ==================

func prompt(label, def string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [%s]: ", label, def)

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return def
	}
	return input
}

func promptChoice(label, def string, allowed map[string]struct{}) string {
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("%s [%s]: ", label, def)

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "" {
			input = def
		}

		if _, ok := allowed[input]; ok {
			return input
		}
		fmt.Println("Некорректный выбор")
	}
}

func confirm(label string, def bool) bool {
	defStr := "y/N"
	if def {
		defStr = "Y/n"
	}

	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("%s (%s): ", label, defStr)

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		if input == "" {
			return def
		}
		if input == "y" || input == "yes" {
			return true
		}
		if input == "n" || input == "no" {
			return false
		}
		fmt.Println("Введите y/n")
	}
}

func promptInt(label string, def int) int {
	for {
		val := prompt(label, strconv.Itoa(def))
		n, err := strconv.Atoi(val)
		if err == nil && n > 0 {
			return n
		}
		fmt.Println("Введите положительное число")
	}
}

// ================== SCAN LOGIC ==================

func buildArgs(mode, customPorts string, detectOS bool) []string {
	args := []string{"-sS", "-T4", "-sV"}

	if customPorts != "" {
		args = append(args, "-p", customPorts)
	} else {
		switch mode {
		case "1":
			args = append(args, "-F")
		case "2":
			args = append(args, "--top-ports", "1000")
		case "3":
			args = append(args, "-p-")
		}
	}

	if detectOS {
		args = append(args, "-O")
	}

	return args
}

func arpDiscovery(network string) []string {
	cmd := exec.Command("nmap", "-sn", "-PR", "-oX", "-", network)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var nmapRun NmapRun
	if err := xml.Unmarshal(out, &nmapRun); err != nil {
		return nil
	}

	var liveHosts []string
	for _, host := range nmapRun.Hosts {
		if strings.ToLower(host.Status.State) != "up" {
			continue
		}
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				liveHosts = append(liveHosts, addr.Addr)
			}
		}
	}

	return liveHosts
}

func classifyDevice(ports []PortInfo, osName, vendor string) (string, int) {
	portSet := make(map[int]struct{}, len(ports))
	for _, p := range ports {
		portSet[p.Port] = struct{}{}
	}

	has := func(port int) bool {
		_, ok := portSet[port]
		return ok
	}

	score := 0
	device := "Unknown"

	switch {
	case has(9100) || has(515) || has(631):
		device = "Printer"
		score = 80
	case has(8291) || strings.Contains(strings.ToLower(osName), "mikrotik"):
		device = "Router (MikroTik)"
		score = 85
	case has(554):
		device = "IP Camera"
		score = 75
	case has(5000) || has(5001):
		device = "NAS"
		score = 75
	case has(3389) && has(445):
		device = "Windows PC"
		score = 85
	case has(22) && has(80):
		device = "Linux Server"
		score = 70
	}

	vendorLow := strings.ToLower(vendor)
	if strings.Contains(vendorLow, "hp") || strings.Contains(vendorLow, "canon") {
		device = "Printer"
		score += 15
	}

	if score == 0 {
		score = 40
	}
	if score > 99 {
		score = 99
	}

	return device, score
}

func scanHost(ip string, baseArgs []string) *ScanResult {
	args := append([]string{}, baseArgs...)
	args = append(args, "-oX", "-", ip)

	cmd := exec.Command("nmap", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var nmapRun NmapRun
	if err := xml.Unmarshal(out, &nmapRun); err != nil || len(nmapRun.Hosts) == 0 {
		return nil
	}

	h := nmapRun.Hosts[0]
	res := &ScanResult{
		IP: ip,
		OS: "Unknown",
	}

	if len(h.Hostnames) > 0 {
		res.Hostname = h.Hostnames[0].Name
	}
	if len(h.Os.OsMatches) > 0 {
		res.OS = h.Os.OsMatches[0].Name
	}

	for _, addr := range h.Addresses {
		if addr.AddrType == "mac" {
			res.MAC = addr.Addr
			res.Vendor = addr.Vendor
		}
	}

	for _, p := range h.Ports {
		if p.State.State == "open" {
			res.Ports = append(res.Ports, PortInfo{
				Port:    p.PortId,
				Service: p.Service.Name,
				Product: p.Service.Product,
				Version: p.Service.Version,
			})
		}
	}

	res.DeviceType, res.Confidence = classifyDevice(res.Ports, res.OS, res.Vendor)
	return res
}

// ================== OUTPUT ==================

func sortResults(results []ScanResult) {
	sort.Slice(results, func(i, j int) bool {
		ip1 := net.ParseIP(results[i].IP).To4()
		ip2 := net.ParseIP(results[j].IP).To4()

		if ip1 == nil && ip2 == nil {
			return results[i].IP < results[j].IP
		}
		if ip1 == nil {
			return false
		}
		if ip2 == nil {
			return true
		}
		return bytes.Compare(ip1, ip2) < 0
	})
}

func outputTerminal(results []ScanResult) {
	fmt.Println("\n--- Smart Scan Results ---")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "IP\tDEVICE\tCONFIDENCE\tOS\tVENDOR")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%s\t%d%%\t%s\t%s\n", r.IP, r.DeviceType, r.Confidence, r.OS, r.Vendor)
	}
	_ = w.Flush()
}

func outputCSV(results []ScanResult) {
	file, err := os.Create("scan_results.csv")
	if err != nil {
		fmt.Println("Ошибка создания CSV:", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	_ = writer.Write([]string{"IP", "Device", "Confidence", "OS", "Vendor"})
	for _, r := range results {
		_ = writer.Write([]string{
			r.IP,
			r.DeviceType,
			strconv.Itoa(r.Confidence),
			r.OS,
			r.Vendor,
		})
	}

	fmt.Println("CSV сохранен")
}

func outputJSON(results []ScanResult) {
	file, err := os.Create("scan_results.json")
	if err != nil {
		fmt.Println("Ошибка создания JSON:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Println("Ошибка записи JSON:", err)
		return
	}

	fmt.Println("JSON сохранен")
}

func outputHTML(results []ScanResult) {
	const tpl = `
<html><body><h1>Smart Scan Results</h1><table border='1'>
<tr><th>IP</th><th>Device</th><th>Confidence</th><th>OS</th><th>Vendor</th></tr>
{{range .}}<tr><td>{{.IP}}</td><td>{{.DeviceType}}</td><td>{{.Confidence}}%</td><td>{{.OS}}</td><td>{{.Vendor}}</td></tr>{{end}}
</table></body></html>`

	t, err := template.New("html").Parse(tpl)
	if err != nil {
		fmt.Println("Ошибка шаблона HTML:", err)
		return
	}

	file, err := os.Create("scan_results.html")
	if err != nil {
		fmt.Println("Ошибка создания HTML:", err)
		return
	}
	defer file.Close()

	if err := t.Execute(file, results); err != nil {
		fmt.Println("Ошибка записи HTML:", err)
		return
	}

	fmt.Println("HTML сохранен")
}

// ================== MAIN ==================

func main() {
	fmt.Println("=== LAN SCANNER ===")

	network := prompt("Подсеть", "192.168.1.0/24")

	fmt.Println("\nРежим:\n1 - FAST\n2 - BALANCED\n3 - FULL")
	mode := promptChoice("Выбор", "2", map[string]struct{}{
		"1": {},
		"2": {},
		"3": {},
	})

	threads := promptInt("Потоки", DefaultThreads)
	detectOS := confirm("Определять ОС?", false)
	customPorts := prompt("Свои порты (Enter = нет)", "")

	fmt.Println("\nВывод:\n1 - Терминал\n2 - CSV\n3 - JSON\n4 - HTML")
	outType := promptChoice("Выбор", "1", map[string]struct{}{
		"1": {},
		"2": {},
		"3": {},
		"4": {},
	})

	deepScan := confirm("Deep scan одного IP?", false)

	args := buildArgs(mode, customPorts, detectOS)

	fmt.Println("\nARP discovery...")
	liveHosts := arpDiscovery(network)
	if len(liveHosts) == 0 {
		fmt.Println("Хосты не найдены")
		return
	}

	fmt.Printf("Найдено хостов: %d. Начинаю сканирование...\n", len(liveHosts))

	var (
		results []ScanResult
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	sem := make(chan struct{}, threads)

	for _, host := range liveHosts {
		wg.Add(1)
		sem <- struct{}{}

		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			if res := scanHost(ip, args); res != nil {
				mu.Lock()
				results = append(results, *res)
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()
	sortResults(results)

	switch outType {
	case "1":
		outputTerminal(results)
	case "2":
		outputCSV(results)
	case "3":
		outputJSON(results)
	case "4":
		outputHTML(results)
	}

	if deepScan {
		ip := prompt("\nIP для deep scan", "")
		if ip != "" {
			fmt.Println("Запуск deep scan...")
			res := scanHost(ip, []string{"-sS", "-T4", "-sV", "-O", "-p-"})
			if res != nil {
				outputTerminal([]ScanResult{*res})
			} else {
				fmt.Println("Deep scan не дал результата")
			}
		}
	}

	fmt.Println("Готово.")
}
