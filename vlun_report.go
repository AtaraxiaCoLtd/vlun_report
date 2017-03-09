package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yhat/scrape"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

const (
	NVD_URI  = "https://web.nvd.nist.gov/view/vuln/detail?vulnId=%s"
	CVSS3_ID = "BodyPlaceHolder_cplPageContent_plcZones_lt_zoneCenter_VulnerabilityDetail_VulnFormView_Vuln3CvssPanel"
	CVSS2_ID = "BodyPlaceHolder_cplPageContent_plcZones_lt_zoneCenter_VulnerabilityDetail_VulnFormView_Vuln2CvssPanel"
)

var REFFERNCES = map[string]string{
	"RedHat":      "https://access.redhat.com/security/cve/%s",
	"Debian":      "https://security-tracker.debian.org/tracker/%s",
	"NVD":         "https://web.nvd.nist.gov/view/vuln/detail?vulnId=%s",
	"CERT":        "https://www.kb.cert.org/vuls/byid?query=%s&searchview=",
	"LWN":         "https://lwn.net/Search/DoSearch?words=%s",
	"oss-sec":     "https://marc.info/?s=%s&l=oss-security",
	"fulldisc":    "https://marc.info/?s=%s&l=full-disclosure",
	"bugtraq":     "https://marc.info/?s=%s&l=bugtraq",
	"exploitdb":   "https://www.exploit-db.com/search/?action=search&cve=%s",
	"metasploit":  "https://www.rapid7.com/db/search?q=%s",
	"Ubuntu":      "https://people.canonical.com/~ubuntu-security/cve/%s.html",
	"Github":      "https://github.com/search?q=\"%s\"",
	"PacketStorm": "https://packetstormsecurity.com/search/?q=%s",
	"bugzilla":    "https://bugzilla.redhat.com/show_bug.cgi?id=%s",
	"twitter":     "https://twitter.com/search?q=%s",
	"CentOS":      "https://www.centos.org/forums/search.php?keywords=%s",
	"cvedetail":   "http://www.cvedetails.com/cve/%s/",
}

func info(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "[+]"+format, a...)
}

func warn(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "[!]"+format, a...)
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: vlun_report -n CVE-2014-0160\n")
}

func main() {
	var flag_cve string

	flag.StringVar(&flag_cve, "numbers", "", "cve numbers")
	flag.StringVar(&flag_cve, "n", "", "cve numbers")
	flag.Parse()

	if flag_cve == "" {
		usage()
		os.Exit(0)
	}

	fmt.Printf("# Vulnerability Report for %s\n\n", flag_cve)

	fmt.Printf("## OverView\n\n")

	fetchNVD(flag_cve)

	fmt.Printf("## Vulnerable software and versions\n\n")

	fetchREF(flag_cve)
}

func fetchREF(cve_num string) {
	fmt.Printf("## Reffernces\n")
	fmt.Printf("\n")
	for key, val := range REFFERNCES {
		var n string
		if key == "exploitdb" {
			n = strings.Replace(cve_num, "CVE-", "", 1)
		} else {
			n = cve_num
		}
		uri := fmt.Sprintf(val, n)
		fmt.Printf(" * [%s](%s)\n", key, uri)
	}
	fmt.Printf("\n")
}

func cvss2markdown(cvssdataset [][]string) {
	fmt.Printf("|KEY|VALUE|\n")
	fmt.Printf("|---|-----|\n")
	for _, node := range cvssdataset {
		fmt.Printf("|%s|%s|\n", node[0], node[1])
	}
}

func fetchNVD(cve_num string) {
	// request and parse the NVD page
	resp, err := http.Get(fmt.Sprintf(NVD_URI, cve_num))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return
	}

	root, err := html.Parse(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return
	}

	cvss3data := fetchCVSS(root, CVSS3_ID)
	cvss2data := fetchCVSS(root, CVSS2_ID)

	if len(cvss3data) > 0 {
		fmt.Printf("## CVSS3\n")
		fmt.Printf("\n")
		cvss2markdown(cvss3data)
		fmt.Printf("\n")
	}
	if len(cvss2data) > 0 {
		fmt.Printf("## CVSS2\n")
		fmt.Printf("\n")
		cvss2markdown(cvss2data)
		fmt.Printf("\n")
	}
}

func fetchCVSS(root *html.Node, id string) [][]string {
	cvssdata := make([][]string, 0)
	CVSS, ok := scrape.Find(root, scrape.ById(id))
	if ok {
		matcherList := func(n *html.Node) bool {
			if n.DataAtom == atom.Div {
				return scrape.Attr(n, "class") == "row"
			}
			return false
		}

		CVSSNode := scrape.FindAll(CVSS, matcherList)
		for _, node := range CVSSNode {
			fields := strings.SplitN(scrape.Text(node), ":", 2)
			if len(fields) > 1 {
				cvssdata = append(cvssdata, fields)
			}
		}
	}
	return cvssdata
}
