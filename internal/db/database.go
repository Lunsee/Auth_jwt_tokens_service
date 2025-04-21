package database

import (
	"Auth_Service/internal/models"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB

func ConnectToPostgres() {
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)

	var err error

	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("❌ Failed to connect to database:", err)
	}
	log.Println("✅ Successfully connected to the database!")

	Migrate()

}

func GetDB() *gorm.DB {
	return db
}

func Migrate() {
	if !db.Migrator().HasTable(&models.Refresh_Tokens{}) {
		err := db.AutoMigrate(&models.Refresh_Tokens{})
		if err != nil {
			log.Fatal(" Migration failed:", err)
		}
		log.Println("Database migrated successfully!")
	} else {
		log.Println("Info: Table already exists, skipping migration.")
	}
}
