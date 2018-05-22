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

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/scrypt"
)

const (
	loginSuccessful = 0
	loginInvalid    = 1
	loginFailed     = 2
	fileError       = 3
)

/* credentials allows to unwrap credentials send in http requests*/
type credentials struct {
	Name     string
	Password string
}

/* token allows to unwrap token send in http requests */
type token struct {
	token string
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

var currentSessions []session

func main() {
	go checkSessions()
	r := mux.NewRouter()
	//This will allow access to the server even if Request originated somewhere else
	allowOrigins := handlers.AllowedOrigins([]string{"*"})
	allowMethods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "OPTIONS", "HEAD"})
	allowHeaders := handlers.AllowedHeaders([]string{"X-Requested-With"})
	r.HandleFunc("/auth", authUser)
	r.HandleFunc("/register", registerUser)
	r.HandleFunc("/checktoken", checkToken)
	r.HandleFunc("/logout", logoutUser)
	r.HandleFunc("/changePassword", changePassword)
	http.Handle("/", r)
	fmt.Println("Listening on port 9000")
	log.Fatal(http.ListenAndServe(":9000", handlers.CORS(allowOrigins, allowMethods, allowHeaders)(r)))
}

func setupResponse(w *http.ResponseWriter, req *http.Request) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-token, Authorization")
}

func authUser(w http.ResponseWriter, r *http.Request) {
	// setupResponse(&w, r)
	// if (*r).Method == "OPTIONS" {
	// 	w.WriteHeader(http.StatusOK)
	// 	w.Write([]byte("200 - OK"))
	// 	fmt.Println("OPTIONS REQUEST IN AUTH")
	// 	return
	// }

	body, _ := ioutil.ReadAll(r.Body)
	res := credentials{}

	json.Unmarshal([]byte(body), &res)

	credCredibility := checkCredentials(res)
	if credCredibility == loginSuccessful {
		issuetoken(w, r)
	} else {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 - Forbidden"))
		return
	}
}

func registerUser(w http.ResponseWriter, r *http.Request) {
	// setupResponse(&w, r)
	// if (*r).Method == "OPTIONS" {
	// 	return
	// }

	body, _ := ioutil.ReadAll(r.Body)
	res := credentials{}
	json.Unmarshal([]byte(body), &res)

}

func issuetoken(w http.ResponseWriter, r *http.Request) {
	rnd := make([]byte, 8)
	rand.Read(rnd)
	ret := token{
		token: fmt.Sprintf("%X", rnd),
	}
	currentSessions = append(currentSessions, session{token: fmt.Sprintf("%X", rnd), TimeLeft: 6})
	js, _ := json.Marshal(ret)
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

func checkToken(w http.ResponseWriter, r *http.Request) {
	setupResponse(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	body, _ := ioutil.ReadAll(r.Body)
	res := token{}
	json.Unmarshal([]byte(body), &res)

	var occured bool
	for _, element := range currentSessions {
		if element.token == res.token {
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
	// setupResponse(&w, r)
	// if (*r).Method == "OPTIONS" {
	// 	return
	// }
	body, _ := ioutil.ReadAll(r.Body)
	res := token{}
	json.Unmarshal([]byte(body), &res)

	var occured bool
	for index, element := range currentSessions {
		if element.token == res.token {
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

func changePassword(w http.ResponseWriter, r *http.Request) {
	//User is required to give the current valid password as well as the username and the new password
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("501 - Not Implemented"))
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
	passCrypt, _ := scrypt.Key([]byte(credentials.Password), salt, 32768, 8, 1, 32)
	if _, err := os.Stat(fmt.Sprintf("%X", nameCrypt)); err == nil {
		state = fileError
		return
	}
	f, _ := os.Create(fmt.Sprintf("%X", nameCrypt))
	storeElement := store{
		Pass: append(passCrypt, salt...),
	}
	js, _ := json.Marshal(storeElement)
	f.Write(js)
	return
}
