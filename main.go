package main

import (
	database "Auth_Service/internal/db"
	"Auth_Service/internal/routes"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	httpSwagger "github.com/swaggo/http-swagger"
)

func main() {
	// Load .env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	//setup port
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080" // default port
	}

	//db
	database.ConnectToPostgres()
	r := mux.NewRouter()

	// Routes
	r.HandleFunc("/get-token/{userID}", routes.GetToken).Methods("GET")
	r.HandleFunc("/refresh-token", routes.Refresh_token).Methods("POST")

	// Swagger
	r.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)

	log.Printf("Server started on port :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
