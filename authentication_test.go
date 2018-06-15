package main

import (
	"crypto/sha512"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestSetPassword(t *testing.T) {
	nameCrypt := sha512.Sum512([]byte("testuser"))
	if _, err := os.Stat("store/" + fmt.Sprintf("%X", nameCrypt)); err == nil {
		os.Remove("store/" + fmt.Sprintf("%X", nameCrypt))
	}
	//Positive
	if registerSuccessful != setPassword(credentials{User: "testuser", Password: "tesTpAssword"}) {
		t.FailNow()

	}
	//Negative
	if registerSuccessful == setPassword(credentials{User: "testuser", Password: "somepass"}) {
		t.FailNow()
	}
	log.Debug("Setting Password test passed.")
}

func TestCheckCredentials(t *testing.T) {
	//Positive
	if loginSuccessful != checkCredentials(credentials{User: "testuser", Password: "tesTpAssword"}) {
		t.FailNow()
	}
	//Negative
	if loginSuccessful == checkCredentials(credentials{User: "testuser", Password: "foo"}) {
		t.FailNow()
	}
	//Negative
	if loginSuccessful == checkCredentials(credentials{User: "test", Password: "foo"}) {
		t.FailNow()
	}
	log.Debug("Credential tests passed.")
}

func TestTokenIssue(t *testing.T) {
	//Positive
	if issueToken() == "" {
		t.FailNow()
	}
	log.Debug("Token Issuing tests passed.")
}

func TestTSessionCheck(t *testing.T) {
	//filled List
	checkSessions()

	currentSessions = append(currentSessions, session{token: "testets", TimeLeft: 1})
	checkSessions()
	if verifyToken("testets") == true {
		t.FailNow()
	}
	log.Debug("Session test passed.")
}

func TestMain(t *testing.T) {

	testingMode = true
	main()
	log.Debug("Main test passed.")
}

func TestVerifyToken(t *testing.T) {
	token := issueToken()
	if verifyToken(token) != true {
		t.FailNow()
	}
	if verifyToken("foobar") == true {
		t.FailNow()
	}
	log.Debug("Token verification passed.")
}

func TestBackgroundDuties(t *testing.T) {
	timeInterval = 100 * time.Millisecond
	backgroundDuties()
	log.Debug("Background tests passed.")
}

func TestConfigInit(t *testing.T) {
	os.Remove("config/config.yml")
	configure()
	configure()
	log.Debug("Configuration tests passed")
}

func TestRSAGeneration(t *testing.T) {
	generateRSA()
	log.Debug("RSA Generation passed.")
}

func TestJWT(t *testing.T) {
	if err := privKey.Validate(); err != nil {
		t.FailNow()
	}
	log.Debug(privKey.Public())
	ts := issueJWT()
	log.Debug(ts)
	e := verfiyJWT(ts)
	if e != nil {
		t.FailNow()
	}
	log.Debug("JWT tests passed, Token valid")
}

// func TestHttpAuth(t *testing.T) {
// 	w := http.ResponseWriter{}
// 	cred := credentials{User: "fred", Password: "test"}
// 	r := http.NewRequest("POST", "stuff", js)
// }
