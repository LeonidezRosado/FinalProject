package main

import (
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"github.com/LeonidezRosado/FinalProject/cookies"

)

//we declare a global variable to hold the secret key
var secretKey []byte

func main() {
	var err error
	//lets Decode the random 64-character hex string to give us a slice containing
	//32 random bytes. For simplicity, Ive hardcoded this hex string but in a
	//real application you should read it in at runtime from a command line
	//flat or enviroment variable 
	secretKey, err = hex.DecodeString("13d6b4dff8f84a10851021ec8608f814570d562c92fe6b5ec4c9f595bcb3234b")
	if err != nil {
		log.Fatal(err)
	}
	//start a web server on the two endpoints

	//creat our server mux instance to handle our http requests
	mux := http.NewServeMux()
	mux.HandleFunc("/set",setCookieHandler)
	mux.HandleFunc("/get", getCookieHandler)

	log.Print("starting on :4000")
	err = http.ListenAndServe(":4000", mux)
	if err != nil {
		log.Fatal(err)
	}
}


func setCookieHandler(w http.ResponseWriter, r *http.Request) {
	//Iniitialze a new cookie containing "Hello world" and some 
	//non-default attributes
	cookie := http.Cookie{
		Name: "exampleCookie",
		Value: "Hello Zoë!",
		Path: "/",
		MaxAge: 3600,
		HttpOnly: true,
		Secure: true,
		SameSite: http.SameSiteLaxMode,
	}

	//Use the http.SetCookies() function to send the cookie to the client
	//Behind the scenes this adds a 'Set-Cookie' header to the response
	//containing the necessary cookie data
	//http.SetCookie(w, &cookie)

	//Write the cookie. if there is an error(due to an ecoding failure on it
	// being too long) then log the error and send a 500 Internal server error
	//response

	//We use the WriteSigned() function we created to pass in teh secret key as
	//the final argument
	err := cookies.WriteEncrypted(w, cookie, secretKey)
	if err != nil {
		log.Print(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	//write a HTTP response as normal
	w.Write([]byte("cookie set!"))

}

func getCookieHandler(w http.ResponseWriter, r *http.Request) {
	 // Retrieve the cookie from the request using its name (which in our case is
	 // "exampleCookie"). If no matching cookie is found, this will return a
	 // http.ErrNoCookie error. We check for this, and return a 400 Bad Request
	 // response to the client.

	 //we Use the ReadSigned() fucnion we created to pass in the secret key as the 
	 //final argument
	 value, err := cookies.ReadEncrypted(r, "exampleCookie", secretKey)
	 if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "cookie not found", http.StatusBadRequest)
		case errors.Is(err, cookies.ErrInvalidValue):
			http.Error(w, "invalid cookie", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	 }

	 //echo out teh cookie value in the response body 
	 w.Write([]byte(value))

}