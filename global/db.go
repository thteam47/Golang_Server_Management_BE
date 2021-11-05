package global

import (
	"context"
	"log"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/go-redis/cache/v8"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var DB mongo.Database
var DBels elasticsearch.Client
var MyRediscache cache.Cache

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}
func connectDB() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(dburl))
	if err != nil {
		log.Fatal("err connect to db", err.Error())
	}
	DB = *client.Database("server")
	// password := "admin"
    // passHash, _ := HashPassword(password)
	// user := User {
	// 	Username: "admin",
	// 	Password: passHash,
	// }
	// DB.Collection("user").InsertOne(ctx, user)
	// if err != nil {
	// 	panic(err)
	// }
}
func GetESClient() {
	cfg := elasticsearch.Config{
		Addresses: []string{
			dbelasticurl,
		},
	}
	clientEL, err := elasticsearch.NewClient(cfg)
	if err != nil {
		log.Fatalf("Error creating the client: %s", err)
	}
	DBels = *clientEL
}
func PongCache() {
	ring := redis.NewRing(&redis.RingOptions{
		Addrs: map[string]string{
			"server1": dbredis,
			//"server2": ":6380",
		},
	})

	err := ring.Ping(context.Background()).Err()
	if err != nil {
		log.Fatalf("Error connect the redis: %s", err)
	}
	memcache := cache.New(&cache.Options{
		Redis:      ring,
		LocalCache: cache.NewTinyLFU(1000, time.Minute),
	})
	MyRediscache = *memcache
}
