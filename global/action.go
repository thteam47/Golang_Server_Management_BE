package global

import "go.mongodb.org/mongo-driver/bson/primitive"

var NilAction Action
type Action struct {
	ID     primitive.ObjectID `bson:"_id,omitempty"`
	IdUser primitive.ObjectID `json:"idUser,omitempty" bson:"idUser,omitempty"`
	Action []string           `json:"action,omitempty" bson:"action,omitempty"`
}
