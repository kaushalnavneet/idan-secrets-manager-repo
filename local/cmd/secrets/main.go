package main

import (
	_ "github.ibm.com/security-services/secrets-manager-vault-plugin-public-cert-secret/local"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	err := ioutil.WriteFile("./.iam_auth.json", []byte(os.Getenv("iam_auth")), os.ModePerm)
	if err != nil {
		log.Fatalln(err)
	}
}
