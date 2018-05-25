package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/scrypt"
)

/******************* structures and enums */

const (
	loginSuccessful    = 0
	loginInvalid       = 1
	loginFailed        = 2
	fileError          = 3
	registerSuccessful = 4
	formatError        = 5
	encryptionError    = 6
)

/* credentials allows to unwrap credentials send in http requests*/
type credentials struct {
	Name     string
	Password string
}

/* token allows to unwrap token send in http requests */
type token struct {
	Token string
}

/* store allows to retrieve previous stored credentials that were once encrypted*/
type store struct {
	Pass []byte
}

/* session allows for storage of currently used tokens and faster authentication of in use user
 */
type session struct {
	token    string
	TimeLeft int
}

type changePass struct {
	Name        string
	Password    string
	NewPassword string
}

/******************* global variables */
var currentSessions []session
var testingMode bool
var timeInterval time.Duration

/******************* HTTP handling */
func main() {
	r := mux.NewRouter()
	//This will allow access to the server even if Request originated somewhere else
	allowOrigins := handlers.AllowedOrigins([]string{"*"})
	allowMethods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "OPTIONS", "HEAD"})
	allowHeaders := handlers.AllowedHeaders([]string{"X-Requested-With"})
	r.HandleFunc("/auth", authUser)
	r.HandleFunc("/register", registerUser)
	r.HandleFunc("/checkToken", checkToken)
	r.HandleFunc("/logout", logoutUser)
	r.HandleFunc("/changePassword", changePassword)
	http.Handle("/", r)
	fmt.Println("Listening on port 9000")
	if testingMode {
		return
	}
	//So this is a quite ugly way to exlude them from testing
	timeInterval = 5 * time.Minute
	go backgroundDuties()
	log.Fatal(http.ListenAndServe(":9000", handlers.CORS(allowOrigins, allowMethods, allowHeaders)(r)))
}

func authUser(w http.ResponseWriter, r *http.Request) {

	body, _ := ioutil.ReadAll(r.Body)
	res := credentials{}

	json.Unmarshal([]byte(body), &res)

	credCredibility := checkCredentials(res)
	if credCredibility == loginSuccessful {
		test := issueToken()
		ret := token{Token: test}
		js, err := json.Marshal(ret)
		if err != nil {
			fmt.Println("error: format error")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
	} else {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 - Forbidden"))
		return
	}
}

func registerUser(w http.ResponseWriter, r *http.Request) {

	body, _ := ioutil.ReadAll(r.Body)
	res := credentials{}
	json.Unmarshal([]byte(body), &res)

	if setPassword(res) == registerSuccessful {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("200 - OK"))
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("401 - Unauthorized"))
	}

}

func checkToken(w http.ResponseWriter, r *http.Request) {
	if (*r).Method == "OPTIONS" {
		return
	}
	body, _ := ioutil.ReadAll(r.Body)
	res := token{}
	json.Unmarshal([]byte(body), &res)

	occured := verifyToken(res.Token)

	if !occured {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 - Forbidden"))
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("200 - OK"))
	}
	return
}

func changePassword(w http.ResponseWriter, r *http.Request) {
	//User is required to give the current valid password as well as the username and the new password
	res := changePass{}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic("Error occured while reading in request body")
	}
	json.Unmarshal([]byte(body), &res)
	cred := credentials{
		Name:     res.Name,
		Password: res.Password,
	}
	credCredibility := checkCredentials(cred)
	if credCredibility == loginSuccessful {
		setPassword(credentials{Name: res.Name, Password: res.NewPassword})
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("200 - OK"))
	} else {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 - Forbidden"))
	}
}

func logoutUser(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	res := token{}
	json.Unmarshal([]byte(body), &res)

	var occured bool
	for index, element := range currentSessions {
		if element.token == res.Token {
			currentSessions = append(currentSessions[:index], currentSessions[index+1:]...)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("200 - Successfully logged out"))
			occured = true
			break
		}
	}
	if !occured {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("500 - An error occured while trying to log off the user"))
	}
	return
}

/****************************** utility functions */
func backgroundDuties() {
	ticker := time.NewTicker(timeInterval)
	for t := range ticker.C {
		checkSessions()
		fmt.Println("Background Tasks", t)
		if testingMode {
			ticker.Stop()
			return
		}
	}
}

func checkSessions() {
	for index, element := range currentSessions {
		element.TimeLeft--
		if element.TimeLeft == 0 {
			currentSessions = append(currentSessions[:index], currentSessions[index+1:]...)
		}
	}
}

func verifyToken(token string) (occured bool) {
	for _, element := range currentSessions {
		if element.token == token {
			element.TimeLeft = 6
			occured = true
			break
		}
	}
	return
}

func checkCredentials(credentials credentials) (state int) {
	storage := store{}
	nameCrypt := sha512.Sum512([]byte(credentials.Name))
	f, err := ioutil.ReadFile(fmt.Sprintf("%X", nameCrypt))
	if err != nil {
		state = loginFailed
		return
	}
	json.Unmarshal(f, &storage)
	passCrypt, _ := scrypt.Key([]byte(credentials.Password), storage.Pass[len(storage.Pass)-8:], 32768, 8, 1, 32)
	if bytes.Equal(append(passCrypt, storage.Pass[len(storage.Pass)-8:]...), storage.Pass) {
		state = loginSuccessful
	} else {
		state = loginInvalid
	}
	return
}

func setPassword(credentials credentials) (state int) {
	salt := make([]byte, 8)
	rand.Read(salt)

	nameCrypt := sha512.Sum512([]byte(credentials.Name))
	passCrypt, err := scrypt.Key([]byte(credentials.Password), salt, 32768, 8, 1, 32)
	if err != nil {
		state = encryptionError
		return
	}

	if _, err = os.Stat(fmt.Sprintf("%X", nameCrypt)); err == nil {
		state = fileError
		return
	}
	f, err := os.Create(fmt.Sprintf("%X", nameCrypt))
	if err != nil {
		state = fileError
		return
	}
	storeElement := store{
		Pass: append(passCrypt, salt...),
	}
	js, err := json.Marshal(storeElement)
	if err != nil {
		state = formatError
		return
	}
	f.Write(js)
	state = registerSuccessful
	return
}

func issueToken() (token string) {
	rnd := make([]byte, 8)
	rand.Read(rnd)

	currentSessions = append(currentSessions, session{token: fmt.Sprintf("%X", rnd), TimeLeft: 6})
	token = fmt.Sprintf("%X", rnd)
	return
}
