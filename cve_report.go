package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/yhat/scrape"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

const (
	NVD_URI  = "https://web.nvd.nist.gov/view/vuln/detail?vulnId=%s"
	CVSS3_ID = "BodyPlaceHolder_cplPageContent_plcZones_lt_zoneCenter_VulnerabilityDetail_VulnFormView_Vuln3CvssPanel"
	CVSS2_ID = "BodyPlaceHolder_cplPageContent_plcZones_lt_zoneCenter_VulnerabilityDetail_VulnFormView_Vuln2CvssPanel"
)

func fetchCVSS(root *html.Node, id string) map[string]string {
	cvssdata := make(map[string]string)
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
			fmt.Printf("%s\n", scrape.Text(node))
		}
	}
	return cvssdata
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

	fetchCVSS(root, CVSS3_ID)
	fetchCVSS(root, CVSS2_ID)
}

func main() {
	var flag_cve string

	flag.StringVar(&flag_cve, "number", "CVE-2017-6074", "cve numbers")
	flag.StringVar(&flag_cve, "n", "CVE-2017-6074", "cve numbers")

	fmt.Fprintf(os.Stderr, "[+] Generate for %s\n", flag_cve)
	fmt.Fprintf(os.Stderr, "[+] Scrape from "+NVD_URI+"\n", flag_cve)

	fetchNVD(flag_cve)
}
