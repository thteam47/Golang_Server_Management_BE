package global

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

var NilUser User

type User struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Username  string             `bson:"username,omitempty"`
	Password  string             `bson:"password,omitempty"`
	FullName  string             `bson:"fullname,omitempty"`
	Email     string             `bson:"email,omitempty"`
	Role      string             `bson:"role,omitempty"`
	CreatedAt time.Time          `json:"created_at,omitempty" bson:"created_at,omitempty"`
	UpdatedAt time.Time          `json:"updated_at,omitempty" bson:"updated_at,omitempty"`
}
