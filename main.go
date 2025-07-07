package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	vault "github.com/hashicorp/vault/api"
)
type ParsedResponse struct {
	Status          string
	RequestMetadata RequestMetadata
	UserData		UserData
	Beamtimes       map[string]BeamtimeDetails
}

type Response struct {
	Status          string `json:"status"`
	RequestMetadata RequestMetadata `json:"request metadata"`
	UserData		UserData `json:"userdata"`
	Beamtimes      map[string]json.RawMessage      `json:"beamtimes"`
}
type RequestMetadata struct {
	URL       string `json:"url"`
	ServiceName   string `json:"service name"`
	Username  string `json:"username"`
}
type UserData struct {
	GivenName  string `json:"given name"`
	FamilyName string `json:"family name"`
}
type BeamtimeDetails struct {
	Proposal       string `json:"proposal"`
	Beamline       string `json:"beamline"`
	ExperimentStart string `json:"experiment start"`
	ExperimentEnd   string `json:"experiment end"`
}

func mariadbConnect(username string,userdata UserData,beamtimeid string, experiment_start string, experiment_end string, proposalNumber string) error{
	// Connect to the MariaDB database
	dsn := "test:test@tcp(haso306s:3307)/test?allowNativePasswords=true"

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction failed: %w", err)
	}
	checkpersonQuery := `SELECT personId FROM Person WHERE login = ? LIMIT 1`
	var personId int64
	// Check if the person already exists in the Person table
	err = tx.QueryRow(checkpersonQuery, username).Scan(&personId)
	if err != nil && err != sql.ErrNoRows {
		tx.Rollback()
		return fmt.Errorf("check person failed: %w", err)
	}
	if personId != 0 {
		fmt.Printf("Person with login %s already exists with personId=%d, skipping insert.\n", username, personId)
	}
	// If the person does not exist, we insert a new record into Person
	
	// 2. Insert into Person
	// Assuming laboratoryId and siteId are nil, personUUID is nil, title, emailAddress, phoneNumber, faxNumber, cache, and externalId are also nil
	// You can modify these values as per your requirements
	// The personUUID is typically a unique identifier,
	// but since it's not provided, we are inserting nil for it.
	if personId == 0 {
		log.Printf("Inserting new person with login %s.\n", username)
		personQuery := `INSERT INTO Person ( laboratoryId, siteId, personUUID, familyName, givenName,
		title, emailAddress, phoneNumber, login, faxNumber, recordTimeStamp, cache, externalId) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		res, err := tx.Exec(personQuery, nil,                      // laboratoryId
  			nil,                      // siteId
  			nil,              // personUUID
  			userdata.FamilyName,                   // familyName
  			userdata.GivenName,                   // givenName
  			nil,                      // title
  			nil,                      // emailAddress
  			nil,                      // phoneNumber
  			username,                   // login
  			nil,                      // faxNumber
  			time.Now(),               // recordTimeStamp
  			nil,                      // cache
  			nil,                      // externalId

  		)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("insert person failed: %w", err)
		}
		personId, err = res.LastInsertId()
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("get personId failed: %w", err)
		}
		fmt.Printf("Inserted new person with personId=%d.\n", personId)
	}
	parts := strings.Split(proposalNumber, "-")
	if len(parts) != 2 {
    	return fmt.Errorf("invalid proposalNumber format")
	}
	proposalNum := parts[1]
	var proposalId int64
	checkQuery := `SELECT proposalId FROM Proposal WHERE proposalNumber = ? LIMIT 1`
	err = tx.QueryRow(checkQuery, proposalNum).Scan(&proposalId)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("Proposal with number %s not found", proposalNum)
		}
		return fmt.Errorf("check proposal failed: %w", err)
	}
	var sessionId int64
	log.Printf("Searching valid session for ProposalId: %d and beamtime id %s", proposalId, beamtimeid)
	seesion_checkQuery := `SELECT sessionId FROM BLSession WHERE proposalId = ? and externalId = ? LIMIT 1`
	beamtimeidInt, err := strconv.Atoi(beamtimeid)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("invalid beamtimeid: %w", err)
	}
	err = tx.QueryRow(seesion_checkQuery, proposalId, beamtimeidInt).Scan(&sessionId)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("Session with proposalId %d not found", proposalId)
		}
		return fmt.Errorf("check session failed: %w", err)
	}
	if sessionId == 0 {
		log.Printf("No valid session found for ProposalId: %d and beamtime id %s", proposalId, beamtimeid)
	}
	log.Printf("Found session with sessionId=%d for proposalId=%d and beamtime id %s", sessionId, proposalId, beamtimeid)
	checkQuery = `SELECT sessionId FROM Session_has_Person WHERE sessionId = ? AND personId = ? LIMIT 1`
	var existingSessionId int64
	// Check if the sessionId and personId already exist in Session_has_Person
	// If they do, we skip the insert
	// If they don't, we insert the new record	
	err = tx.QueryRow(checkQuery, sessionId, personId).Scan(&existingSessionId)
	if err != nil && err != sql.ErrNoRows {
		tx.Rollback()
		return fmt.Errorf("check session_has_person failed: %w", err)
	}
	if existingSessionId != 0 {
		log.Printf("Session with sessionId=%d and personId=%d already exists, skipping insert.\n", sessionId, personId)
		tx.Commit()
		defer db.Close()
		return nil
	}
	// If the record does not exist, we insert it
	if existingSessionId == 0 {
		log.Printf("Inserting new session with sessionId=%d and personId=%d.\n", sessionId, personId)
	}
	// Insert the new record into Session_has_Person
	// Assuming role is "Co-Investigator" and remote is 0 (not remote)
	linkQuery := ` INSERT INTO Session_has_Person (sessionId, personId, role, remote) VALUES (?, ?, ?, ?)`
	_, err = tx.Exec(linkQuery, sessionId, personId, "Co-Investigator", 0)
	if err != nil {
			tx.Rollback()
		return fmt.Errorf("insert into Session_has_Person failed: %w", err)
	}

	// 4. Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit failed: %w", err)
	}

	fmt.Printf("Inserted personId=%d, sessionId=%d and linked them.\n", personId, sessionId)
	defer db.Close()
	return nil

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
func fetchBeamtimes(w http.ResponseWriter,username string,doorToken string, doorServiceAccount string, doorServiceAuth string, token string) (ParsedResponse, error) {
	url := fmt.Sprintf("https://doortest.desy.de/api/v1.0/remotecontrol/user/%s", username)
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
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	var r Response
	if err := json.Unmarshal(body, &r); err != nil {
		log.Fatalf("Error unmarshalling JSON: %v", err)
	}
	if r.Status != "OK" {
		log.Fatalf("API request failed with status: %s", r.Status)
		return ParsedResponse{}, fmt.Errorf("API request failed with status: %s", r.Status)
	}
	if len(r.Beamtimes) == 0 {
		log.Println("No beamtimes found for the user")
		w.WriteHeader(http.StatusUnauthorized)
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprint(w, `<html><head><title>Unauthorized</title></head><body><h1>Unauthorized</h1><p>No user exists in DOOR.</p></body></html>`)
		return ParsedResponse{}, fmt.Errorf("no beamtimes found for the user")
	}
	// Print the parsed response
	// fmt.Println("Parsed Response:")
	// // fmt.Println("Status:", r.Status)
	// fmt.Println("Request Metadata:")	
	// println("Response Status:", r.Status)
	// println("Request URL:", r.RequestMetadata.URL)
	// println("Request Service Name:", r.RequestMetadata.ServiceName)
	// println("Request Username:", r.RequestMetadata.Username)
	// println("User Family Name:", r.UserData.FamilyName)
	// println("User Given Name:", r.UserData.GivenName)
	// println("Beamtimes Count:", r.Beamtimes)
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
	return ParsedResponse {
		Status:          r.Status,
		RequestMetadata: r.RequestMetadata,
		UserData:        r.UserData,
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
	// fmt.Println("Received Headers:")
	Groups := r.Header.Get("X-Auth-Request-Groups")
	var username string = r.Header.Get("X-Auth-Request-Preferred-Username")
    if username == "" {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
	// fmt.Printf("Username: %s\n", username)
	Groups_value := strings.Split(Groups,",")
	fmt.Printf("Groups: %v\n", Groups_value)
	fmt.Printf("Groups: %s\n", r.Header.Get("X-Auth-Request-groups"))
	// for name, values := range r.Header {
		
	// 	for _, value := range values {
			
	// 		fmt.Printf("%s: %s\n", name, value)
	// 	}
	// }
	result, err := fetchBeamtimes(w,username, secrets["door-token"], secrets["door-service-account"], secrets["door-service-account-secret"], secrets["token"])
	if err != nil || len(result.Beamtimes) == 0 {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
	// println("Result:", result.Status)
	// println("Request URL:", result.RequestMetadata.URL)
	// println("Request Service Name:", result.RequestMetadata.ServiceName)
	// println("Request Username:", result.RequestMetadata.Username)
	// println("Beamtimes Count:", len(result.Beamtimes))
	for id, bt := range result.Beamtimes {
		fmt.Println("-----------------------------")
		fmt.Printf("Beamtime ID: %s\n", id)
		fmt.Printf("Proposal: %s\n", bt.Proposal)
		fmt.Printf("Beamline: %s\n", bt.Beamline)
		fmt.Printf("Experiment Start: %s\n", bt.ExperimentStart)
		fmt.Printf("Experiment End: %s\n", bt.ExperimentEnd)
		fmt.Println("-----------------------------")
		// Call mariadbConnect for each beamtime
		err = mariadbConnect(username,result.UserData, id, bt.ExperimentStart, bt.ExperimentEnd, bt.Proposal)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error connecting to MariaDB: %v", err), http.StatusInternalServerError)
			return
		}
		fmt.Printf("Successfully connected to MariaDB and inserted data for beamtime ID: %s\n", id)
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("Error fetching beamtimes: %v", err), http.StatusInternalServerError)
		return
	}
	for name, values := range r.Header {
    for _, value := range values {
        w.Header().Add(name, value)
    }
	}
	w.WriteHeader(http.StatusOK)
	
	// redirectURL := "https://h5web.haszvmp.desy.de"
	// http.Redirect(w, r, redirectURL, http.StatusFound) // 302 Found
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
