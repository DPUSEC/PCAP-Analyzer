package schemas

import (
	"time"
)

// Rules modeli
type Rules struct {
	ID          string    `bson:"_id,omitempty"`
	Name        string    `bson:"name"`
	Description string    `bson:"description"`
	Path        string    `bson:"path"`
	CreatorID   string    `bson:"creator_id"`
	CreatedAt   time.Time `bson:"created_at"`
	UpdatedAt   time.Time `bson:"updated_at"`
}
