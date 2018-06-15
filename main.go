package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	config "github.com/jwuensche/go-config-yaml"
	"github.com/op/go-logging"
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
	User     string
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
	User        string
	Password    string
	NewPassword string
}

/******************* global variables */
var (
	currentSessions []session
	testingMode     bool
	timeInterval    time.Duration
	privKey         *rsa.PrivateKey
)

/******************* config variables */
var (
	port     string
	location string
)

/******************* logger init */
var log = logging.MustGetLogger("authentication")

var format = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc} | %{shortfile} : %{level:.8s} %{id:03x}%{color:reset} %{message}`,
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
	} else {
		generateRSA()
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
		ret := token{Token: issueJWT()}
		js, err := json.Marshal(ret)
		if err != nil {
			log.Error("Format error")
			return
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
	body, _ := ioutil.ReadAll(r.Body)
	res := token{}
	json.Unmarshal([]byte(body), &res)

	if e := verfiyJWT(res.Token); e != nil {
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
		User:     res.User,
		Password: res.Password,
	}
	credCredibility := checkCredentials(cred)
	if credCredibility == loginSuccessful {
		setPassword(credentials{User: res.User, Password: res.NewPassword})
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
	nameCrypt := sha512.Sum512([]byte(credentials.User))
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

	nameCrypt := sha512.Sum512([]byte(credentials.User))
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
	rnd := make([]byte, 16)
	rand.Read(rnd)

	currentSessions = append(currentSessions, session{token: fmt.Sprintf("%X", rnd), TimeLeft: 6})
	token = fmt.Sprintf("%X", rnd)
	return
}

func issueJWT() (token string) {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"token": issueToken(),
		"nbf":   time.Now(),
	})
	if err := privKey.Validate(); err != nil {
		log.Error("Generated key pair invalid")
		os.Exit(1)
		return
	}
	token, err := tok.SignedString(privKey)
	if err != nil {
		log.Error("Signing of Token failed", err)
	}
	return
}

func verfiyJWT(tokenstring string) (e error) {
	token, err := validateJWT(tokenstring)
	if err != nil {
		log.Error("Verification of JWT failed")
		e = errors.New("Invalid JWT")
		return
	}
	if verifyToken(token) == true {
		e = nil
		return
	}
	e = errors.New("Token Invalid")
	return
}

func validateJWT(tokenstring string) (token string, e error) {
	jwtok, err := jwt.Parse(tokenstring, func(t *jwt.Token) (interface{}, error) {
		if _, err := t.Method.(*jwt.SigningMethodRSA); !err {
			return nil, fmt.Errorf("Invalid type %v", t.Header["alg"])
		}
		return privKey.Public(), nil
	})
	if err != nil {
		log.Error("Parsing of JWT failed")
	}
	if claims, ok := jwtok.Claims.(jwt.MapClaims); ok && jwtok.Valid {
		token = claims["token"].(string)
		e = nil
	} else {
		token = ""
		e = errors.New("Invalid JWT")
	}
	return
}

func generateRSA() {
	log.Notice("Generating RSA key")
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Error("Generation of RSA key failed")
		os.Exit(1)
	}
	if err = key.Validate(); err != nil {
		log.Error("Generated key pair invalid")
		os.Exit(1)
	}
	privKey = key
}

// Config represents the structural idea of the config yaml file used to give configure optios to the Authentication
// service
type Config struct {
	Port int `yaml:"port"`
}

func configure() (e error) {
	configFile, e := config.NewConfig("config/", "config", false, 0722)
	if e != nil {
		return
	}
	if v, err := configFile.Get("port"); err == nil {
		log.Notice("Config File found. Applying ...")
		port = ":" + v
	} else {
		log.Notice("No config found. Using default configuration")
		log.Error(err)
		configFile.Set("port", "9000")
		v, err := configFile.Get("port")
		if err != nil {
			return
		}
		port = ":" + v
	}
	return
}

func loggerInitilization() {
	backend1 := logging.NewLogBackend(os.Stderr, "", 0)
	backend1Formatter := logging.NewBackendFormatter(backend1, format)
	backend1Leveled := logging.AddModuleLevel(backend1)
	backend1Leveled.SetLevel(logging.ERROR, "")
	logging.SetBackend(backend1Leveled, backend1Formatter)
}
