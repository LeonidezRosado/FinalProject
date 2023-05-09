package main

import (
	"bytes"
    "encoding/gob"
    "encoding/hex"
    "errors"
    "fmt"
    "log"
    "net/http"
    //"strings"

	"github.com/LeonidezRosado/FinalProject/cookies"

)

//we declare a global variable to hold the secret key
var secret []byte

//We declare a custom type User struct which reperesnts our users name and age
type User struct {
	Name string
	Age int
}

func main() {
	//we need to tell the encoding/gob package about the Go type 
	//that we want to encode. We do this by passing "an instance" of the type
	//to the gob.Register(). In this case we pass a pointer to an intiialized (but
	//emtpy) instance of the User struct
	gob.Register(&User{})

	var err error
	//lets Decode the random 64-character hex string to give us a slice containing
	//32 random bytes. For simplicity, Ive hardcoded this hex string but in a
	//real application you should read it in at runtime from a command line
	//flat or enviroment variable 
	secret, err = hex.DecodeString("13d6b4dff8f84a10851021ec8608f814570d562c92fe6b5ec4c9f595bcb3234b")
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
	//Initialize a User struct containing the data tha twe want to store in
	//the cookie 
	user := User{Name: "Alice", Age: 21}

	//Initialize a buffer to hold the Gob-encoded data
	var buf bytes.Buffer

	//Gob-encode the user data, storing the encoded output in the buffer buf.
	err := gob.NewEncoder(&buf).Encode(&user)
	if err != nil {
		log.Println(err)
		http.Error(w, "sever error", http.StatusInternalServerError)
		return
	}


	//we nwo Call the buf.String() to get the gob-encoded value as a string and set it 
	//as the cookie value 
	cookie := http.Cookie{
		Name: "exampleCookie",
		Value: buf.String(),
		Path: "/",
		MaxAge: 3600,
		HttpOnly: true,
		Secure: true,
		SameSite: http.SameSiteLaxMode,
	}

	

	//we use writeSinged() to write the encrypted cookie containing the 
	//gob-encoded data to the response writer
	//We write an ecrypted cookie containing the gob encoded data as nomral 
	err = cookies.WriteSigned(w, cookie, secret)
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	//write a HTTP response as normal
	w.Write([]byte("cookie set!"))

}

func getCookieHandler(w http.ResponseWriter, r *http.Request) {
	 
	 //We Read the gob-encoded value from the encrypted cookie
	 //using the ReadSigned function
	gobEncodedValue, err := cookies.ReadSigned(r, "exampleCookie", secret)
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
	 
	 //we create new User struct to store the decoded gob-encoded data.
	 var user User

	 //we create a new buffer and write the gob-encoded data to it
	 //so that it can be decoded back into the user struct
	 var buf bytes.Buffer
	 buf.WriteString(gobEncodedValue)
 
	 //we read the data from the buffer rather than directly from the
	 //string, since that is not supported by the gob package
	 err = gob.NewDecoder(&buf).Decode(&user)
	 if err != nil {
		fmt.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	 }

	 //Print the user information in the response 
	 fmt.Fprintf(w, "Name: %q\n", user.Name)
	 fmt.Fprintf(w, "Age: %d\n", user.Age)

}