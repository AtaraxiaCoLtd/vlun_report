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

func main() {
	var flag_cve string

	flag.StringVar(&flag_cve, "numbers", "CVE-2017-6074,CVE-2014-0160", "cve numbers")
	flag.StringVar(&flag_cve, "n", "CVE-2017-6074,CVE-2014-0160", "cve numbers")

	fmt.Printf("# Vulnerability Report for %s\n", flag_cve)

	cve_nums := strings.Split(flag_cve, ",")
	for _, num := range cve_nums {
		fetchNVD(num)
	}
}

func cvss2markdown(cvssdataset [][]string) {
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
		fmt.Printf("## CVSS3 for %s\n", cve_num)
		cvss2markdown(cvss3data)
	}
	if len(cvss2data) > 0 {
		fmt.Printf("## CVSS2 for %s\n", cve_num)
		cvss2markdown(cvss2data)
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
