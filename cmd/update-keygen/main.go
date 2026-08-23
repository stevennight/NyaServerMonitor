package main

import (
	"flag"
	"fmt"
	"os"

	sharedcrypto "nyaservermonitor/internal/shared/crypto"
)

func main() {
	privatePath := flag.String("private-key", "nyasm-update-private.key", "private key output path")
	publicPath := flag.String("public-key", "nyasm-update-public.key", "public key output path")
	flag.Parse()
	publicKey, privateKey, err := sharedcrypto.GenerateSigningKey()
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*privatePath, []byte(privateKey+"\n"), 0o600); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*publicPath, []byte(publicKey+"\n"), 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("public key: %s\nprivate key: %s\n", publicKey, *privatePath)
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
