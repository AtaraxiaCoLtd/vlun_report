package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/yhat/scrape"
	"golang.org/x/net/html"
)

const (
	CVSS3_ID = "BodyPlaceHolder_cplPageContent_plcZones_lt_zoneCenter_VulnerabilityDetail_VulnFormView_Vuln3CvssPanel"
	NVD_URI  = "https://web.nvd.nist.gov/view/vuln/detail?vulnId=%s"
)

func main() {
	var flag_cve string

	flag.StringVar(&flag_cve, "number", "CVE-2017-6074", "cve numbers")
	flag.StringVar(&flag_cve, "n", "CVE-2017-6074", "cve numbers")

	// debug messages
	fmt.Printf("[+] Generate for %s\n", flag_cve)
	fmt.Printf("[+] Scrape from "+NVD_URI, flag_cve)

	// request and parse the front page
	resp, err := http.Get(fmt.Sprintf(NVD_URI, flag_cve))
	if err != nil {
		panic(err)
	}

	root, err := html.Parse(resp.Body)
	if err != nil {
		panic(err)
	}

	CVSS3, ok := scrape.Find(root, scrape.ById(CVSS3_ID))
}
