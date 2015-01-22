package main

import (
  "flag"
  "fmt"
  "io/ioutil"
  "encoding/json"
  "net/http"
  "net/url"
  "reflect"
  )

const GetSaltURL string = "https://keybase.io/_/api/1.0/getsalt.json"

type User struct {
  Salt string
}

type Session struct {
  CSRFToken string
  LoginSession string
}

func getSalt(email_or_username string) (Session, User, error) {
  fmt.Println(email_or_username)

  getSaltUrl, err := url.Parse(GetSaltURL)
  if err != nil {
    return Session{}, User{}, err
  }

  fmt.Println(getSaltUrl)

  params := url.Values{}
  params.Add("email_or_username", email_or_username)

  getSaltUrl.RawQuery = params.Encode()

  fmt.Println(getSaltUrl)

  resp, err := http.Get(getSaltUrl.String())
  if err != nil {
    return Session{}, User{}, err
  }
  defer resp.Body.Close()

  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    return Session{}, User{}, err
  }

  fmt.Println(string(body))

  var saltParams map[string]interface{}
  err = json.Unmarshal(body, &saltParams)
  if err != nil {
    return Session{}, User{}, err
  }

//  fmt.Println(saltParams)
  fmt.Println("----------RETURNED VALUES----------")
  for k, v := range saltParams {
    fmt.Println(k, ":", v, ":", reflect.TypeOf(v))
  }

  salt := saltParams["salt"].(string)
  csrfToken := saltParams["csrf_token"].(string)
  loginSession := saltParams["login_session"].(string)

  fmt.Println("CSRF Token:", csrfToken)
  fmt.Println("Salt:", salt)
  fmt.Println("Login Session:", loginSession)
//  fmt.Printf("%+v", saltParams)

  session := Session{CSRFToken: csrfToken, LoginSession: loginSession}
  me := User{Salt: salt}

  return session, me, nil

}

func main() {
  user := flag.String("user", "", "User name or e-mail address.")
  passphrase := flag.String("passphrase", "", "Passphrase.")

  flag.Parse()
  fmt.Println("User: ", *user)
  fmt.Println("Passphrase: ", *passphrase)

  session, me, err := getSalt("christopherburg")
  if err != nil {
    panic(err)
  }

  fmt.Println("Session:", "CSRFToken:", session.CSRFToken, ":LoginSession:", session.LoginSession)
  fmt.Println("Me:", me)
}
