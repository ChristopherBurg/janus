package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"

	"golang.org/x/crypto/scrypt"
)

// Session stores information related to identifying a user to Keybase.io.
type Session struct {
	CSRFToken     string
	SessionCookie string
}

// User stores information related to a Keybase.io user.
type User struct {
	Name string
	Salt string

	Identity *Session
}

// The URL used to get a user's salt.
const GetSaltURL string = "https://keybase.io/_/api/1.0/getsalt.json"

// The URL used to log into Keybase.io.
const LoginURL string = "https://keybase.io/_/api/1.0/login.json"

// Performs an HTTP GET operation against a selected URL with specified
// parameters. The function will return the response's body and any cookies
// received since those are the values that Keybase's API rely on.
func get(URL string, params url.Values) ([]byte, []*http.Cookie, error) {

	getURL, err := url.Parse(GetSaltURL)
	if err != nil {
		return nil, nil, err
	}

	getURL.RawQuery = params.Encode()

	client := &http.Client{}
	request, err := http.NewRequest("GET", getURL.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	return body, resp.Cookies(), nil
}

// Performs an HTTP POST operation against a selected URL with the specified
// JSON values. The function will return the response's body and any cookies
// received since those are the values that Keybase's API rely on.
func post(URL string, params map[string]string) ([]byte, []*http.Cookie, error) {

	jsonValues, err := json.Marshal(params)
	if err != nil {
		return nil, nil, err
	}

	client := &http.Client{}
	request, err := http.NewRequest("POST", URL, bytes.NewBuffer(jsonValues))
	if err != nil {
		return nil, nil, err
	}

	request.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	return body, resp.Cookies(), nil
}

// Takes the body returned from Keybase.io's getsalt API call and parses into
// retrieves the desired data from the returned JSON data.
func parseSalt(body []byte) (string, string, string, error) {
	var saltParams map[string]interface{}
	err := json.Unmarshal(body, &saltParams)
	if err != nil {
		return "", "", "", err
	}

	salt := saltParams["salt"].(string)
	csrfToken := saltParams["csrf_token"].(string)
	loginSession := saltParams["login_session"].(string)

	return salt, csrfToken, loginSession, nil
}

func (user *User) getSalt() (string, error) {
	params := url.Values{}
	params.Add("email_or_username", user.Name)

	body, _, err := get(GetSaltURL, params)
	if err != nil {
		return "", err
	}

	salt, csrfToken, loginSession, err := parseSalt(body)
	if err != nil {
		return "", err
	}

	user.Salt = salt
	user.Identity.CSRFToken = csrfToken

	return loginSession, nil
}

// Hash's a user's password use Scrypt.
func hashPassphrase(salt string, passphrase string) ([]byte, error) {
	decodedSalt, err := hex.DecodeString(salt)
	if err != nil {
		return nil, err
	}

	hash, err := scrypt.Key([]byte(passphrase), decodedSalt, int(math.Pow(2, 15)), 8, 1, 224)
	if err != nil {
		return nil, err
	}

	pwh := hash[192:224]

	return pwh, nil
}

// Creates an HMAC from the user's hashed password at the current login session.
func getHMAC(pwh []byte, loginSession string) ([]byte, error) {
	b64Session, err := base64.StdEncoding.DecodeString(loginSession)
	if err != nil {
		return nil, err
	}

	hmacPWH := hmac.New(sha512.New, pwh)
	hmacPWH.Write(b64Session)

	return hmacPWH.Sum(nil), nil
}

// Login creates a session for a user.
func (user *User) Login(passphrase string) error {
	loginSession, err := user.getSalt()
	if err != nil {
		return err
	}

	pwh, err := hashPassphrase(user.Salt, passphrase)
	if err != nil {
		return err
	}

	hmacPWH, err := getHMAC(pwh, loginSession)
	if err != nil {
		return nil
	}

	loginValues := map[string]string{"email_or_username": user.Name,
		"hmac_pwh":      hex.EncodeToString(hmacPWH),
		"login_session": loginSession}

	body, cookies, err := post(LoginURL, loginValues)
	if err != nil {
		return err
	}

	for _, cookie := range cookies {
		if cookie.Name == "session" {
			user.Identity.SessionCookie = cookie.Value
		}
	}

	fmt.Println("Login Body:", string(body))

	return nil
}

func main() {
	user := flag.String("user", "", "User name or e-mail address.")
	passphrase := flag.String("passphrase", "", "Passphrase.")

	flag.Parse()

	session := Session{}
	me := User{Name: *user, Identity: &session}

	err := me.Login(*passphrase)
	if err != nil {
		panic(err)
	}

	// salt, csrfToken, loginSession, err := GetSalt(*user)
	// if err != nil {
	// 	panic(err)
	// }

	//	Login(*user, salt, loginSession, *passphrase)

	fmt.Println("Returned GetSalt values for user", *user, ".")
	fmt.Println("salt:", me.Salt)
	fmt.Println("csrfToken:", me.Identity.CSRFToken)
	// fmt.Println("loginSession:", loginSession)
}
