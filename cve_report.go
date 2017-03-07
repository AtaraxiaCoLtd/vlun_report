package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/yhat/scrape"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

const (
	NVD_URI  = "https://web.nvd.nist.gov/view/vuln/detail?vulnId=%s"
	CVSS3_ID = "BodyPlaceHolder_cplPageContent_plcZones_lt_zoneCenter_VulnerabilityDetail_VulnFormView_Vuln3CvssPanel"
	CVSS2_ID = "BodyPlaceHolder_cplPageContent_plcZones_lt_zoneCenter_VulnerabilityDetail_VulnFormView_Vuln2CvssPanel"
)

func main() {
	var flag_cve string

	flag.StringVar(&flag_cve, "number", "CVE-2017-6074", "cve numbers")
	flag.StringVar(&flag_cve, "n", "CVE-2017-6074", "cve numbers")

	fmt.Printf("[+] Generate for %s\n", flag_cve)
	fmt.Printf("[+] Scrape from "+NVD_URI+"\n", flag_cve)

	// request and parse the front page
	resp, err := http.Get(fmt.Sprintf(NVD_URI, flag_cve))
	if err != nil {
		panic(err)
	}

	root, err := html.Parse(resp.Body)
	if err != nil {
		panic(err)
	}

	// Scrape CVSS3 from NVD
	CVSS3, ok := scrape.Find(root, scrape.ById(CVSS3_ID))
	if ok {
		fmt.Printf("[+] Detect CVSS3 dataset\n")
		matcherList := func(n *html.Node) bool {
			if n.DataAtom == atom.Div {
				return scrape.Attr(n, "class") == "row"
			}
			return false
		}

		CVSS3Node := scrape.FindAll(CVSS3, matcherList)
		for _, node := range CVSS3Node {
			fmt.Printf("%s\n", scrape.Text(node))
		}
	}

	// Scrape CVSS2 from NVD
	CVSS2, ok := scrape.Find(root, scrape.ById(CVSS2_ID))
	if ok {
		fmt.Printf("[+] Detect CVSS2 dataset\n")
		matcherList := func(n *html.Node) bool {
			if n.DataAtom == atom.Div {
				return scrape.Attr(n, "class") == "row"
			}
			return false
		}

		CVSS2Node := scrape.FindAll(CVSS2, matcherList)
		for _, node := range CVSS2Node {
			fmt.Printf("%s\n", scrape.Text(node))
		}
	}
}
