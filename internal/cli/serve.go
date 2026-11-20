package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/hourx/kai-harness/pkg/serve"
)

// cmdServe runs the service face: read-only HTTP and JSON over the same
// workspace the CLI reads. It blocks until interrupted.
//
// Read-only on purpose. The CLI is where mutations happen, because a mutation
// typed by the operator has a scope gate and a printed artifact attached to it;
// the same call arriving over a socket would not.
func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", serve.DefaultAddr, "bind address; port 0 asks the kernel for a free one")
	token := fs.String("token", os.Getenv("KAI_SERVE_TOKEN"), `bearer token, or "auto" to generate one`)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: kai serve [--addr host:port] [--token T|auto]")
		fmt.Fprintln(os.Stderr, "  read-only HTTP/JSON view of the workspace; loopback by default")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		return fail(errors.New("usage: kai serve [--addr host:port] [--token T|auto]"))
	}

	automatic := *token == "auto"
	tok := *token
	if automatic {
		generated, err := serve.NewToken()
		if err != nil {
			return fail(err)
		}
		tok = generated
	}

	srv := serve.New("", tok) // an empty home resolves to the workspace root per request
	// Bind before printing: with --addr 127.0.0.1:0 the kernel picks the port, and
	// the operator can only use an address that is already real.
	ln, err := srv.Listen(*addr)
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("kai serve — http://%s\n", hintAddr(ln.Addr().String()))
	fmt.Printf("home      %s\n", srv.HomeRoot())
	if tok == "" {
		fmt.Println("auth      none (loopback only)")
	} else if automatic {
		fmt.Printf("auth      token  %s\n", tok)
	} else {
		fmt.Println("auth      token (from --token or KAI_SERVE_TOKEN)")
	}
	fmt.Println("read-only  mutations stay in the CLI; ctrl-c to stop")

	if err := srv.ServeListener(ctx, ln); err != nil {
		return fail(err)
	}
	fmt.Println("stopped")
	return 0
}

// hintAddr turns a bind address into something the operator can paste into a
// phone browser. A wildcard bind is reported with this machine's outbound IP,
// which is what a device on the same network has to use.
func hintAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if serve.IsLoopback(host) {
		return net.JoinHostPort(host, port)
	}
	if ip := outboundIP(); ip != "" {
		return net.JoinHostPort(ip, port)
	}
	return addr
}

// outboundIP reports the address this host would use to reach the outside. The
// UDP socket is never connected to anything, so this sends no traffic.
func outboundIP() string {
	conn, err := net.Dial("udp", "192.0.2.1:9") // TEST-NET-1, reserved and unroutable
	if err != nil {
		return ""
	}
	defer conn.Close()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}
