package models

import (
	"time"

	"github.com/google/uuid"
)

type Refresh_Tokens struct {
	ID            int       `json:"id" gorm:"primaryKey"`
	Refresh_token string    `json:"refresh_token" gorm:"column:refresh_token"`
	Lookup_hash   string    `json:"lookup_hash" gorm:"column:lookup_hash"`
	UserID        uuid.UUID `gorm:"not null"`
	IP            string    `json:"ip" gorm:"column:ip"`
	CreatedAt     time.Time `json:"createdAt" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt     time.Time `json:"updatedAt" gorm:"column:updated_at;autoUpdateTime"`
}
