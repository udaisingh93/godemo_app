package main

import (
	"fmt"
	"log"
	"os"
	"net/http"
	"strings"
	"io/ioutil"
	"encoding/json"
	vault "github.com/hashicorp/vault/api"
)
type ParsedResponse struct {
	Status          string
	RequestMetadata RequestMetadata
	Beamtimes       map[string]BeamtimeDetails
}

type Response struct {
	Status          string `json:"status"`
	RequestMetadata RequestMetadata `json:"request metadata"`
	Beamtimes      map[string]json.RawMessage      `json:"beamtimes"`
}
type RequestMetadata struct {
	URL       string `json:"url"`
	ServiceName   string `json:"service name"`
	Username  string `json:"username"`
}

type BeamtimeDetails struct {
	Proposal       string `json:"proposal"`
	Beamline       string `json:"beamline"`
	ExperimentStart string `json:"experiment start"`
	ExperimentEnd   string `json:"experiment end"`
}
func getdoorcredentials(url string , secretPath string)(map[string]string, error){
	config := vault.DefaultConfig()
	config.Address = url // Change to your Vault address
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Optionally use VAULT_TOKEN from environment
	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		return nil, fmt.Errorf("VAULT_TOKEN is not set in the environment")
	}
	client.SetToken(vaultToken)
	// Read the secret from the given path
	secret, err := client.Logical().Read(secretPath)
	if err != nil || secret == nil {
		return nil, fmt.Errorf("failed to read secret from Vault: %w", err)
	}

	rawData, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected secret format")
	}
	secrets := make(map[string]string)
	for key, value := range rawData {
		strVal, ok := value.(string)
		if ok {
			secrets[key] = strVal
		}
	}
	return secrets, nil
}
// Fetch beamtimes from the API and print details for a specific beamtime
func fetchBeamtimes(username string,doorToken string, doorServiceAccount string, doorServiceAuth string, token string) {
	url := fmt.Sprintf("https://doortest.desy.de/api/v1.0/remotecontrol/user/%s", username)
	fmt.Println("creedentials:", doorToken, doorServiceAccount, doorServiceAuth, token)
	req, err := http.NewRequest("GET", url, nil )
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", token)
    req.Header.Set("x-door-token", doorToken)
    req.Header.Set("x-door-service-account", doorServiceAccount)
    req.Header.Set("x-door-service-auth", doorServiceAuth)
	for key, values := range req.Header {
    for _, value := range values {
        fmt.Printf("Header: %s => %s\n", key, value)
    }
}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
	}
	if resp == nil {
		log.Fatal("Received nil response from server")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		log.Fatal("Unauthorized access - check your credentials")
	}
	if resp.StatusCode == http.StatusForbidden {
		log.Fatal("Forbidden access - you do not have permission to access this resource")
	}
	if resp.StatusCode == http.StatusNotFound {
		log.Fatal("Resource not found - check the URL or resource ID")
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Non-OK HTTP status: %s", resp.Status)
	}
	defer resp.Body.Close()
	// Read and parse the response body
	body, err := ioutil.ReadAll(resp.Body)
	println("Response Status:", resp.Status)
	println("Response Headers:", resp.Header)
	println("Response Body:", string(body))
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	var r Response
	if err := json.Unmarshal(body, &r); err != nil {
		log.Fatalf("Error unmarshalling JSON: %v", err)
	}
	println("Response Status:", r.Status)
	println("Request URL:", r.RequestMetadata.URL)
	println("Request Service Name:", r.RequestMetadata.ServiceName)
	println("Request Username:", r.RequestMetadata.Username)
	println("Beamtimes Count:", r.Beamtimes)
	beamtimeMap := make(map[string]BeamtimeDetails)
	// Print all beamtimes
	for key, raw := range r.Beamtimes {
		if key == "count" {
			continue // Skip the count key
		}
		var bt BeamtimeDetails
		if err := json.Unmarshal(raw, &bt); err != nil {
			log.Fatalf("Error parsing beamtime data for key %s: %v", key, err)
		}
		beamtimeMap[key] = bt
	}
	// Print details for each beamtime
	for id, bt := range beamtimeMap {
		fmt.Println("-----------------------------")
		// fmt.Printf("Beamtime ID: %s\n", id)
		fmt.Printf("Beamtime ID: %s\n", id)
		fmt.Printf("Proposal: %s\n", bt.Proposal)
		fmt.Printf("Beamline: %s\n", bt.Beamline)
		fmt.Printf("Experiment Start: %s\n", bt.ExperimentStart)
		fmt.Printf("Experiment End: %s\n", bt.ExperimentEnd)
		fmt.Println("-----------------------------")
	}
	return ParsedResponse{
		Status:          raw.Status,
		RequestMetadata: raw.RequestMetadata,
		Beamtimes:       beamtimeMap,
	}, nil
}
func handler(w http.ResponseWriter, r *http.Request) {
	// Log headers
	secrets, err := getdoorcredentials("https://haso306s.desy.de:8200", "/kv/data/auth2redirect")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error fetching credentials: %v", err), http.StatusInternalServerError)
		return
	}
	fmt.Println("Received Headers:")
	Groups := r.Header.Get("X-Auth-Request-Groups")
	var username string = r.Header.Get("X-Auth-Request-Preferred-Username")
	if username == "" {
		http.Error(w, "Username not found in headers", http.StatusBadRequest)
		return
	}
	fmt.Printf("Username: %s\n", username)
	Groups_value := strings.Split(Groups,",")
	fmt.Printf("Groups: %v\n", Groups_value)
	fmt.Printf("Groups: %s\n", r.Header.Get("X-Auth-Request-groups"))
	for name, values := range r.Header {
		
		for _, value := range values {
			
			fmt.Printf("%s: %s\n", name, value)
		}
	}
	fetchBeamtimes(username, secrets["door-token"], secrets["door-service-account"], secrets["door-service-account-secret"], secrets["token"])
	// Redirect to another page

	redirectURL := "https://h5web.haszvmp.desy.de"
	http.Redirect(w, r, redirectURL, http.StatusFound) // 302 Found
}

func main() {
	// Fetch credentials from Vault
	http.HandleFunc("/", handler)
	port := ":8080"
	fmt.Printf("Server is running at http://localhost%s\n", port)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
