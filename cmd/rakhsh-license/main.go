// Command rakhsh-license is the license issuer. It holds the private Ed25519
// seed and mints signed Rakhsh licenses. Run it only on a machine you control.
//
//	rakhsh-license serve [--addr :8900]   web form to issue licenses (default)
//	rakhsh-license gen --name "Ali" --days 365 [--features '*'] [--plan pro]
//	rakhsh-license keygen                  print a fresh keypair (one-time setup)
//
// The seed is read from $RAKHSH_LICENSE_SEED or the file ./seed.txt (base64 of
// 32 bytes). Keep it secret — anyone with it can mint licenses.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"html"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"rakhsh/internal/license"
)

func seed() string {
	if v := strings.TrimSpace(os.Getenv("RAKHSH_LICENSE_SEED")); v != "" {
		return v
	}
	if b, err := os.ReadFile("seed.txt"); err == nil {
		return strings.TrimSpace(string(b))
	}
	fmt.Fprintln(os.Stderr, "no seed: set RAKHSH_LICENSE_SEED or create seed.txt (run 'rakhsh-license keygen')")
	os.Exit(1)
	return ""
}

func main() {
	if len(os.Args) < 2 {
		os.Args = append(os.Args, "serve")
	}
	switch os.Args[1] {
	case "keygen":
		cmdKeygen()
	case "gen":
		cmdGen(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: rakhsh-license serve|gen|keygen")
		os.Exit(2)
	}
}

func cmdKeygen() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sd := priv.Seed()
	fmt.Println("# Put this public key into internal/license/license.go (pubKeyB64):")
	fmt.Println("PUBLIC  =", base64.StdEncoding.EncodeToString(pub))
	fmt.Println("# Keep this seed secret (seed.txt / RAKHSH_LICENSE_SEED):")
	fmt.Println("SEED    =", base64.StdEncoding.EncodeToString(sd))
}

func mint(name, plan, features string, days int) (string, error) {
	var exp int64
	if days > 0 {
		exp = time.Now().AddDate(0, 0, days).Unix()
	}
	feats := []string{"*"}
	if strings.TrimSpace(features) != "" && features != "*" {
		feats = nil
		for _, f := range strings.Split(features, ",") {
			if f = strings.TrimSpace(f); f != "" {
				feats = append(feats, f)
			}
		}
	}
	lic := license.License{
		ID:       strconv.FormatInt(time.Now().UnixNano(), 36),
		Name:     name,
		Plan:     plan,
		Expiry:   exp,
		Features: feats,
		Issued:   time.Now().Unix(),
	}
	return license.Sign(seed(), lic)
}

func cmdGen(args []string) {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	name := fs.String("name", "", "buyer name/label")
	plan := fs.String("plan", "pro", "plan label")
	days := fs.Int("days", 365, "valid days (0 = never expires)")
	feats := fs.String("features", "*", "comma list, or * for all")
	_ = fs.Parse(args)
	if *name == "" {
		fmt.Fprintln(os.Stderr, "--name required")
		os.Exit(2)
	}
	lic, err := mint(*name, *plan, *feats, *days)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(lic)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8900", "listen address")
	_ = fs.Parse(args)
	// fail fast if the seed is missing
	_ = seed()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var out, errMsg string
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			days, _ := strconv.Atoi(r.FormValue("days"))
			lic, err := mint(r.FormValue("name"), r.FormValue("plan"), r.FormValue("features"), days)
			if err != nil {
				errMsg = err.Error()
			} else {
				out = lic
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, page(out, errMsg))
	})
	fmt.Printf("Rakhsh license issuer on http://localhost%s\n", *addr)
	_ = http.ListenAndServe(*addr, nil)
}

func page(out, errMsg string) string {
	res := ""
	if errMsg != "" {
		res = `<div class="err">` + html.EscapeString(errMsg) + `</div>`
	} else if out != "" {
		res = `<label>لایسنس (برای مشتری کپی کن)</label><textarea readonly onclick="this.select()" rows="4">` + html.EscapeString(out) + `</textarea>`
	}
	return `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>صدور لایسنس رخش</title>
<style>:root{font-family:Vazirmatn,system-ui,sans-serif}
body{background:#0b0f17;color:#eaf1fb;display:grid;place-items:center;min-height:100vh;margin:0}
.card{background:#141b26;border:1px solid #243040;border-radius:16px;padding:1.6rem;width:min(460px,92vw);display:grid;gap:.8rem}
h1{margin:.2rem 0;font-size:1.4rem;background:linear-gradient(135deg,#4f8cff,#2bd4d9);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
label{font-size:.85rem;color:#8aa0b7}
input,textarea,button{width:100%;box-sizing:border-box;background:#1b2432;border:1px solid #2e3f58;color:#eaf1fb;padding:.6rem;border-radius:10px;font:inherit}
button{background:linear-gradient(135deg,#4f8cff,#8b7bff);border:0;font-weight:600;cursor:pointer;margin-top:.4rem}
.err{color:#ff93a0}.row{display:flex;gap:.6rem}.row>div{flex:1}</style></head>
<body><form class="card" method="post">
<h1>صدور لایسنس رخش</h1>
<div><label>نام مشتری</label><input name="name" required placeholder="علی"></div>
<div class="row"><div><label>مدت (روز، ۰=دائمی)</label><input name="days" type="number" value="365"></div>
<div><label>پلن</label><input name="plan" value="pro"></div></div>
<div><label>امکانات (یا * برای همه)</label><input name="features" value="*"></div>
<button>ساخت لایسنس</button>` + res + `</form></body></html>`
}
