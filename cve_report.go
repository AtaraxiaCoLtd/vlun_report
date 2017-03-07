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
	fmt.Printf("%v\n", cvss3data)
	cvss2data := fetchCVSS(root, CVSS2_ID)
	fmt.Printf("%v\n", cvss2data)
}

func main() {
	var flag_cve string

	flag.StringVar(&flag_cve, "number", "CVE-2017-6074", "cve numbers")
	flag.StringVar(&flag_cve, "n", "CVE-2017-6074", "cve numbers")

	fmt.Fprintf(os.Stderr, "[+] Generate for %s\n", flag_cve)
	fmt.Fprintf(os.Stderr, "[+] Scrape from "+NVD_URI+"\n", flag_cve)

	fetchNVD(flag_cve)
}
