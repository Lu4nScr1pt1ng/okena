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
// Each request's line, query arguments and fields go through the rules (CRS
// phases 1 and 2), and its body too when the addon has `phases request_body`
// (its first `body` bytes: up to 16 KiB). A request the rules
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
	"sync"
	"time"

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

	go sweep()
	log.Fatal(addon.Run(func(r *addon.Request, a *addon.Answer) {
		switch {
		case r.Phase == addon.PhaseLog:
			if k := take(r.Stream); k != nil {
				end(k.tx)
			}
		case r.IsResponse():
			judgeResponse(waf, r, a)
		default:
			judge(waf, r, a, *detect)
		}
	}, addon.Options{Workers: *workers}))
}

// transactions kept from a request to its response (the addon's response
// phases: the CRS's phases 3 and 4) or its log
type kept struct {
	tx types.Transaction
	at time.Time
}

var txs = struct {
	sync.Mutex
	m map[addon.StreamID]*kept
}{m: map[addon.StreamID]*kept{}}

func keep(id addon.StreamID, tx types.Transaction) {
	txs.Lock()
	txs.m[id] = &kept{tx, time.Now()}
	txs.Unlock()
}

func take(id addon.StreamID) *kept {
	txs.Lock()
	defer txs.Unlock()
	k := txs.m[id]
	delete(txs.m, id)
	return k
}

func end(tx types.Transaction) {
	tx.ProcessLogging()
	tx.Close()
}

// a response that never came (okena answered, the client went): its
// transaction ends after a minute
func sweep() {
	for range time.Tick(10 * time.Second) {
		txs.Lock()
		for id, k := range txs.m {
			if time.Since(k.at) > time.Minute {
				end(k.tx)
				delete(txs.m, id)
			}
		}
		txs.Unlock()
	}
}

func judgeResponse(waf coraza.WAF, r *addon.Request, a *addon.Answer) {
	k := take(r.Stream)
	var tx types.Transaction
	if k != nil {
		tx = k.tx
	} else {
		tx = waf.NewTransaction()
		tx.ProcessURI(r.Target, r.Method, "HTTP/1.1")
	}
	for _, f := range r.Headers {
		tx.AddResponseHeader(f.Name, f.Value)
	}
	it := tx.ProcessResponseHeaders(r.Status, "HTTP/1.1")
	if it == nil && len(r.Body) > 0 {
		if it, _, _ = tx.WriteResponseBody(r.Body); it == nil {
			it, _ = tx.ProcessResponseBody()
		}
	}
	if it != nil {
		ids := matched(tx)
		log.Printf("the response to %s %s: %s (rules %s)", r.Method, r.Target, it.Action, ids)
		status := it.Status
		if status < 200 || status > 599 {
			status = 403
		}
		a.Respond(status)
		a.Add("content-type", "text/plain")
		a.Body([]byte(strconv.Itoa(status) + " withheld by the web application firewall\n"))
	}
	if r.Last || it != nil {
		end(tx)
	} else {
		keep(r.Stream, tx)
	}
}

func judge(waf coraza.WAF, r *addon.Request, a *addon.Answer, detect bool) {
	tx := waf.NewTransaction()
	ended := false
	defer func() {
		if !ended {
			end(tx)
		}
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
	if it == nil && len(r.Body) > 0 {
		// (the addon's phases request_body: the body, or its first `body` bytes)
		it, _, _ = tx.WriteRequestBody(r.Body)
	}
	if it == nil {
		// phase 2: the CRS's rules on the arguments, the query's and the body's
		it, _ = tx.ProcessRequestBody()
	}
	if it == nil {
		if detect {
			if ids := matched(tx); ids != "" {
				a.Set("x-waf-rules", ids)
			}
		}
		if !r.Last { // its response (or log) comes later: the same transaction
			ended = true
			keep(r.Stream, tx)
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
