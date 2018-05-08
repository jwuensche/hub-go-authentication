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

	"golang.org/x/crypto/scrypt"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

type Credentials struct {
	Name     string
	Password string
}

type Token struct {
	Token string
}

type Store struct {
	Pass []byte
}

type Session struct {
	Token    string
	TimeLeft int
}

var currentSessions []Session

func main() {
	go checkSessions()
	r := mux.NewRouter()
	//This will allow access to the server even if Request originated somewhere else
	corsObj := handlers.AllowedOrigins([]string{"*"})
	r.HandleFunc("/auth", authUser)
	r.HandleFunc("/register", registerUser)
	r.HandleFunc("/checkToken", checkToken)
	http.Handle("/", r)
	fmt.Println("Listening on port 9000")
	log.Fatal(http.ListenAndServe(":9000", handlers.CORS(corsObj)(r)))
}

func authUser(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	res := Credentials{}
	json.Unmarshal([]byte(body), &res)

	nameCrypt := sha512.Sum512([]byte(res.Name))
	store := Store{}
	f, err := ioutil.ReadFile(fmt.Sprintf("%X", nameCrypt))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 - Forbidden"))
		return
	}
	json.Unmarshal(f, &store)

	passCrypt, _ := scrypt.Key([]byte(res.Password), store.Pass[len(store.Pass)-8:], 32768, 8, 1, 32)

	if bytes.Equal(append(passCrypt, store.Pass[len(store.Pass)-8:]...), store.Pass) {
		exemptToken(w, r)
	} else {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 - Forbidden"))
		return
	}
}

func registerUser(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	res := Credentials{}
	json.Unmarshal([]byte(body), &res)

	salt := make([]byte, 8)
	rand.Read(salt)

	nameCrypt := sha512.Sum512([]byte(res.Name))
	passCrypt, _ := scrypt.Key([]byte(res.Password), salt, 32768, 8, 1, 32)
	f, _ := os.Create(fmt.Sprintf("%X", nameCrypt))
	storeElement := Store{
		Pass: append(passCrypt, salt...),
	}
	js, _ := json.Marshal(storeElement)
	f.Write(js)
}

func exemptToken(w http.ResponseWriter, r *http.Request) {
	rnd := make([]byte, 8)
	rand.Read(rnd)
	ret := Token{
		Token: fmt.Sprintf("%X", rnd),
	}
	currentSessions = append(currentSessions, Session{Token: fmt.Sprintf("%X", rnd), TimeLeft: 6})
	js, _ := json.Marshal(ret)
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

func checkToken(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	res := Token{}
	json.Unmarshal([]byte(body), &res)

	var occured bool
	for _, element := range currentSessions {
		if element.Token == res.Token {
			occured = true
			break
		}
	}
	w.Header().Set("Content-Type", "application/json")
	js, _ := json.Marshal(res)
	if !occured {
		js, _ = json.Marshal(Token{Token: "false"})
	}
	w.Write(js)
}

func checkSessions() {
	for _, element := range currentSessions {
		element.TimeLeft -= 1
		if element.TimeLeft == 0 {
			element.Token = ""
		}
	}
}
