package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/op/go-logging"
	"golang.org/x/crypto/scrypt"
	yaml "gopkg.in/yaml.v2"
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
var (
	currentSessions []session
	testingMode     bool
	timeInterval    time.Duration
)

/******************* config variables */
var (
	port     string
	location string
)

/******************* logger init */
var log = logging.MustGetLogger("authentication")

var format = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc}|%{shortfile} : %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

/******************* HTTP handling */
func main() {
	loggerInitilization()
	configure()
	r := mux.NewRouter()
	//This will allow access to the server even if Request originated somewhere else
	allowOrigins := handlers.AllowedOrigins([]string{"*"})
	allowMethods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "OPTIONS", "HEAD"})
	allowHeaders := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type"})
	r.HandleFunc("/auth", authUser)
	r.HandleFunc("/register", registerUser)
	r.HandleFunc("/checkToken", checkToken)
	r.HandleFunc("/logout", logoutUser)
	r.HandleFunc("/changePassword", changePassword)
	http.Handle("/", r)
	log.Notice("Serving at port", port)
	if testingMode {
		return
	}
	//So this is a quite ugly way to exlude them from testing
	timeInterval = 5 * time.Minute
	go backgroundDuties()
	log.Fatal(http.ListenAndServe(port, handlers.CORS(allowOrigins, allowMethods, allowHeaders)(r)))
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
			log.Error("Format error")
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
	for _ = range ticker.C {
		checkSessions()
		log.Info("Background Task")
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
	f, err := ioutil.ReadFile("store/" + fmt.Sprintf("%X", nameCrypt))
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

	if _, err = os.Stat("store/" + fmt.Sprintf("%X", nameCrypt)); err == nil {
		state = fileError
		return
	}
	os.MkdirAll("store", 0722)
	f, err := os.Create("store/" + fmt.Sprintf("%X", nameCrypt))
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

// Config represents the structural idea of the config yaml file used to give configure optios to the Authentication
// service
type Config struct {
	Port int `yaml:"port"`
}

func configure() {
	_, err := os.Stat("config/config.yml")
	if err == nil {
		log.Notice("Config File found. Applying ...")
		configFile, err := ioutil.ReadFile("config/config.yml")
		if err != nil {
			log.Error("Opening Config failed")
			return
		}
		config := Config{}
		err = yaml.Unmarshal([]byte(configFile), &config)
		if err != nil {
			log.Error("Configuration file is invalid")
			return
		}
		port = ":" + strconv.Itoa(config.Port)
	} else {
		log.Notice("No config found. Using default configuration")
		os.MkdirAll("config", 0722)
		configFile, err := os.Create("config/config.yml")
		config := Config{Port: 9000}
		fmt.Println(config)
		if err != nil {
			log.Error("Opening Config failed")
			return
		}
		yml, err := yaml.Marshal(config)
		if err != nil {
			log.Error("Encoding default config failed")
			return
		}
		configFile.Write(yml)
		configFile.Close()
		port = ":9000"
	}
}

func loggerInitilization() {
	backend1 := logging.NewLogBackend(os.Stderr, "", 0)
	backend1Formatter := logging.NewBackendFormatter(backend1, format)
	backend1Leveled := logging.AddModuleLevel(backend1)
	backend1Leveled.SetLevel(logging.ERROR, "")
	logging.SetBackend(backend1Leveled, backend1Formatter)
}
