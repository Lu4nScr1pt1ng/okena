// coraza-okena: a WAF addon for okena on Coraza (github.com/corazawaf/coraza)
// with the OWASP Core Rule Set built in.
//
//	addon waf {
//	    run /usr/local/bin/coraza-okena -paranoia 1
//	    timeout 50ms
//	    on_error allow
//	}
//	route /* { addon waf; to pool app }
//
// Each request's line, query arguments and fields go through the rules
// (CRS phases 1 and 2: what can be judged before a body). A request the rules
// refuse gets their status (403 unless a rule says otherwise) and a short
// body; the rules that matched are logged to okena's log. -detect only logs
// and lets everything through, telling the backend the matched rules'
// ids in x-waf-rules.
//
//	-rules FILE      directives of your own, after the CRS's (or instead: -crs=false)
//	-paranoia N      the CRS paranoia level, 1 to 4 (default 1)
//	-workers N       requests judged at once (default: the CPUs)
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"

	addon "github.com/Lu4nScr1pt1ng/okena/sdk/go"
)

func main() {
	rules := flag.String("rules", "", "a file of SecLang directives, read after the CRS")
	crs := flag.Bool("crs", true, "load the OWASP Core Rule Set")
	paranoia := flag.Int("paranoia", 1, "CRS paranoia level (1-4)")
	detect := flag.Bool("detect", false, "only log what matches, block nothing")
	workers := flag.Int("workers", runtime.NumCPU(), "requests judged at once")
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("coraza-okena: ")

	var d strings.Builder
	if *crs {
		d.WriteString("Include @coraza.conf-recommended\n")
		d.WriteString("Include @crs-setup.conf.example\n")
		fmt.Fprintf(&d, "SecAction \"id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d\"\n", *paranoia)
		d.WriteString("Include @owasp_crs/*.conf\n")
	}
	if *rules != "" {
		b, err := os.ReadFile(*rules)
		if err != nil {
			log.Fatal(err)
		}
		d.Write(b)
		d.WriteByte('\n')
	}
	if *detect {
		d.WriteString("SecRuleEngine DetectionOnly\n")
	} else {
		d.WriteString("SecRuleEngine On\n")
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(d.String()))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ready: CRS %v, paranoia %d, %s", *crs, *paranoia, map[bool]string{true: "detection only", false: "blocking"}[*detect])

	log.Fatal(addon.Run(func(r *addon.Request, a *addon.Answer) {
		judge(waf, r, a, *detect)
	}, addon.Options{Workers: *workers}))
}

func judge(waf coraza.WAF, r *addon.Request, a *addon.Answer, detect bool) {
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()
	ip := r.ClientIP()
	client := ""
	if ip != nil {
		client = ip.String()
	}
	tx.ProcessConnection(client, 0, "", 0)
	tx.ProcessURI(r.Target, r.Method, "HTTP/1.1")
	for _, f := range r.Headers {
		tx.AddRequestHeader(f.Name, f.Value)
		if strings.EqualFold(f.Name, "host") {
			tx.SetServerName(f.Value)
		}
	}
	it := tx.ProcessRequestHeaders()
	if it == nil {
		// phase 2 with no body: the CRS's rules on the query's arguments
		it, _ = tx.ProcessRequestBody()
	}
	if it == nil {
		if detect {
			if ids := matched(tx); ids != "" {
				a.Set("x-waf-rules", ids)
			}
		}
		return
	}
	ids := matched(tx)
	log.Printf("%s %s from %s: %s (rules %s)", r.Method, r.Target, client, it.Action, ids)
	status := it.Status
	if status < 200 || status > 599 || it.Action != "deny" {
		status = 403
	}
	a.Respond(status)
	a.Add("content-type", "text/plain")
	a.Body([]byte(strconv.Itoa(status) + " refused by the web application firewall\n"))
}

// the ids of the rules that matched and say something (the CRS's own
// bookkeeping rules left out)
func matched(tx types.Transaction) string {
	var ids []string
	for _, m := range tx.MatchedRules() {
		if m.Message() == "" {
			continue
		}
		ids = append(ids, strconv.Itoa(m.Rule().ID()))
	}
	return strings.Join(ids, ",")
}
