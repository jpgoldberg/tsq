package main

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/digitorus/timestamp"
)

// ExampleCreateRequest_ParseResponse demonstrates the creation of a time-stamp request, sending
// it to the server and parsing the response.
// nolint: govet
func main() {

	// eventually we will use command line arguments to set these

	fresh_tsr := false // do we request a new one or read to a file?
	write_tsr := false // do we spit out a base64 encoded tsr?

	filename := "find-the-key.txt"
	tsa_host := "https://freetsa.org/tsr"
	tsr_file := "tsr.txt"

	var resp []byte
	if fresh_tsr {
		r, err := stamp_file(filename, tsa_host)
		if err != nil {
			log.Fatal(err)
		}
		resp = r
	} else {
		r, err := tsr_from_file(tsr_file)
		if err != nil {
			log.Fatal(err)
		}
		resp = r
	}

	if write_tsr {
		tsr_string := base64.StdEncoding.EncodeToString(resp)
		fmt.Println(tsr_string)
	} else {
		fmt.Println(tsr_info(resp))
	}

}

func tsr_from_file(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	decoder := base64.NewDecoder(base64.StdEncoding, file)
	tsr, err := ioutil.ReadAll(decoder)
	if err != nil {
		return nil, fmt.Errorf("failed to read data from file: %v", err)
	}
	return tsr, nil
}

func stamp_file(filename string, service string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}
	defer file.Close()

	// We are just going to go with sensible defaults here
	tsq, err := timestamp.CreateRequest(file, &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	tsr, err := http.Post(service, "application/timestamp-query", bytes.NewReader(tsq))
	if err != nil {
		return nil, fmt.Errorf("Failed to get response: %v", err)
	}

	if tsr.StatusCode > 200 {
		return nil, fmt.Errorf("response is not OK: %v", err)
	}

	resp, err := ioutil.ReadAll(tsr.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	return resp, nil
}

func tsr_info(tsr []byte) (string, error) {

	tsResp, err := timestamp.ParseResponse(tsr)
	if err != nil {
		return "", fmt.Errorf("could not parse: %v", err)
	}

	s := fmt.Sprintf("Data-hash:\t%x\n", tsResp.HashedMessage)
	s += fmt.Sprintf("TSA-Policy:\t%v\n", tsResp.Policy)
	if len(tsResp.Certificates) > 0 {
		s += fmt.Sprintf("TSA-Org:\t%v\n", tsResp.Certificates[0].Subject.Organization)
	}
	return s, nil
}
