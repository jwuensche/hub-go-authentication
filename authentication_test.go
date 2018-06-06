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
	if registerSuccessful != setPassword(credentials{Name: "testuser", Password: "tesTpAssword"}) {
		t.FailNow()
	}
	//Negative
	if registerSuccessful == setPassword(credentials{Name: "testuser", Password: "somepass"}) {
		t.FailNow()
	}
}

func TestCheckCredentials(t *testing.T) {
	//Positive
	if loginSuccessful != checkCredentials(credentials{Name: "testuser", Password: "tesTpAssword"}) {
		t.FailNow()
	}
	//Negative
	if loginSuccessful == checkCredentials(credentials{Name: "testuser", Password: "foo"}) {
		t.FailNow()
	}
	//Negative
	if loginSuccessful == checkCredentials(credentials{Name: "test", Password: "foo"}) {
		t.FailNow()
	}
}

func TestTokenIssue(t *testing.T) {
	//Positive
	if issueToken() == "" {
		t.FailNow()
	}
}

func TestTSessionCheck(t *testing.T) {
	//filled List
	checkSessions()

	currentSessions = append(currentSessions, session{token: "testets", TimeLeft: 1})
	checkSessions()
	if verifyToken("testets") == true {
		t.FailNow()
	}
}

func TestMain(t *testing.T) {
	testingMode = true
	main()
}

func TestVerifyToken(t *testing.T) {
	token := issueToken()
	if verifyToken(token) != true {
		t.FailNow()
	}
	if verifyToken("foobar") == true {
		t.FailNow()
	}
}

func TestBackgroundDuties(t *testing.T) {
	timeInterval = 100 * time.Millisecond
	backgroundDuties()
}

func TestConfigInit(t *testing.T) {
	os.Remove("config/config.yml")
	configure()
	configure()
}

// func TestHttpAuth(t *testing.T) {
// 	w := http.ResponseWriter{}
// 	cred := credentials{Name: "fred", Password: "test"}
// 	r := http.NewRequest("POST", "stuff", js)
// }
