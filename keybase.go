package main

import (
  "bytes"
  "crypto/hmac"
  "crypto/sha512"
  "flag"
  "fmt"
  "io/ioutil"
  "encoding/base64"
  "encoding/json"
  "encoding/hex"
//  "hash"
  "math"
  "net/http"
  "net/url"
  // "reflect"
  "golang.org/x/crypto/scrypt"
  )

const GetSaltURL string = "https://keybase.io/_/api/1.0/getsalt.json"
const LoginURL string = "https://keybase.io/_/api/1.0/login.json"

type User struct {
  Name string
  Salt string
}

type Session struct {
  CSRFToken string
  LoginSession string
}

func (user *User) GetSalt() (Session, error) {
  fmt.Println(user.Name)

  getSaltUrl, err := url.Parse(GetSaltURL)
  if err != nil {
    return Session{}, err
  }

//  fmt.Println(getSaltUrl)

  params := url.Values{}
  params.Add("email_or_username", user.Name)

  getSaltUrl.RawQuery = params.Encode()

//  fmt.Println(getSaltUrl)

  resp, err := http.Get(getSaltUrl.String())
  if err != nil {
    return Session{}, err
  }
  defer resp.Body.Close()

  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    return Session{}, err
  }

//  fmt.Println(string(body))

  var saltParams map[string]interface{}
  err = json.Unmarshal(body, &saltParams)
  if err != nil {
    return Session{}, err
  }

//  fmt.Println(saltParams)
  // fmt.Println("----------RETURNED VALUES----------")
  // for k, v := range saltParams {
  //   fmt.Println(k, ":", v, ":", reflect.TypeOf(v))
  // }

  user.Salt = saltParams["salt"].(string)
  csrfToken := saltParams["csrf_token"].(string)
  loginSession := saltParams["login_session"].(string)

  // fmt.Println("CSRF Token:", csrfToken)
  // fmt.Println("Salt:", user.Salt)
  // fmt.Println("Login Session:", loginSession)
//  fmt.Printf("%+v", saltParams)

  session := Session{CSRFToken: csrfToken, LoginSession: loginSession}

  return session, nil

}

func (user *User) Login(session Session, passphrase string) (error) {

  decodedSalt, err := hex.DecodeString(user.Salt)
  if err != nil {
    return err
  }

  hash, err := scrypt.Key([]byte(passphrase), decodedSalt, int(math.Pow(2, 15)), 8, 1, 224)
  if err != nil {
    return err
  }

  pwh := hash[192:224]

  b64Session, err := base64.StdEncoding.DecodeString(session.LoginSession)
  if err != nil {
    return err
  }

  fmt.Println("Hash:", pwh)
  fmt.Println("Hash HEX:", hex.EncodeToString(pwh))
  fmt.Println("Hash b64:", b64Session)

  hmac := hmac.New(sha512.New, pwh)
  hmac.Write(b64Session)

  fmt.Println("HMAC:", hmac.Sum(nil))
  fmt.Println("HMAC STD B64:", base64.StdEncoding.EncodeToString(hmac.Sum(nil)))
  fmt.Println("HMAC URL B64:", base64.URLEncoding.EncodeToString(hmac.Sum(nil)))
  fmt.Println("HMAC HEX:", hex.EncodeToString(hmac.Sum(nil)))


  loginValues := map[string]string{"email_or_username" : user.Name,
                                   "hmac_pwh" : hex.EncodeToString(hmac.Sum(nil)),
                                   "login_session" : session.LoginSession}

  loginJSON, err := json.Marshal(loginValues)
  if err != nil {
    return err
  }

  fmt.Println("JSON Login Data:", string(loginJSON))

//  return err

  // params := url.Values{}
  // params.Add("email_or_username", user.Name)
  // params.Add("hmac_pwh", hex.EncodeToString(hmac.Sum(nil)))
  // params.Add("login_session", session.LoginSession)

  client := &http.Client{}
  r, err := http.NewRequest("POST", LoginURL, bytes.NewBuffer(loginJSON))
//  r, err := http.NewRequest("POST", LoginURL, bytes.NewBufferString(params.Encode()))
  if err != nil {
    return err
  }

  r.Header.Add("Content-Type", "application/json")
  fmt.Println(r)
  fmt.Println(r.Body)

//  return err

  resp, err := client.Do(r)
  if err != nil {
    return err
  }
  defer resp.Body.Close()

  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    return err
  }

  fmt.Println(string(body))

  return err
}

func main() {
  user := flag.String("user", "", "User name or e-mail address.")
  passphrase := flag.String("passphrase", "", "Passphrase.")

   flag.Parse()
  // fmt.Println("User: ", *user)
  // fmt.Println("Passphrase: ", *passphrase)

  me := User{Name: *user}

  session, err := me.GetSalt()
  if err != nil {
    panic(err)
  }

  err = me.Login(session, *passphrase)

  // fmt.Println("Session:", "CSRFToken:", session.CSRFToken, ":LoginSession:", session.LoginSession)
  // fmt.Println("Me:", me)
}
