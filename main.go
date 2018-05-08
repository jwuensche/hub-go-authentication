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

/* Credentials allows to unwrap Credentials send in http requests*/
type Credentials struct {
	Name     string
	Password string
}

/* Token allows to unwrap Token send in http requests */
type Token struct {
	Token string
}

/* Store allows to retrieve previous stored Credentials that were once encrypted*/
type Store struct {
	Pass []byte
}

/* Session allows for storage of currently used tokens and faster authentication of in use user
 */
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
	r.HandleFunc("/logout", logoutUser)
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

	if _, err := os.Stat(fmt.Sprintf("%X", nameCrypt)); err == nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 - Forbidden"))
		return
	}
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
			element.TimeLeft = 6
			occured = true
			break
		}
	}

	if !occured {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 - Forbidden"))
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("200 - OK"))
	}
	return
}

func checkSessions() {
	for index, element := range currentSessions {
		element.TimeLeft--
		if element.TimeLeft == 0 {
			currentSessions = append(currentSessions[:index], currentSessions[index+1:]...)
		}
	}
}

func logoutUser(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	res := Token{}
	json.Unmarshal([]byte(body), &res)

	var occured bool
	for index, element := range currentSessions {
		if element.Token == res.Token {
			currentSessions = append(currentSessions[:index], currentSessions[index+1:]...)
			occured = true
			break
		}
	}
	if !occured {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("500 - An error occured while trying to log off the user"))
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("200 - Successfully logged out"))
	}
	return
}
