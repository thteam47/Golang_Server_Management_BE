package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"example.com/m/global"
	"github.com/go-redis/cache/v8"
)

// func rClient() *redis.Client {
// 	client := redis.NewClient(&redis.Options{
// 		Addr: "localhost:6379",
// 	})
// 	return client
// }
// func ping(client *redis.Client) error {
// 	pong, err := client.Ping().Result()
// 	if err != nil {
// 		return err
// 	}
// 	// Output: PONG <nil>
// 	fmt.Println(pong)
// 	return nil
// }

// func set(client *redis.Client) error {
// 	err := client.Set("name", "43636", 0).Err()
// 	if err != nil {
// 		return err
// 	}

// 	err = client.Set("country", "Philippines", 0).Err()
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }
// func get(client *redis.Client) error {
// 	nameVal, err := client.Get("name").Result()
// 	if err != nil {
// 		return (err)
// 	}
// 	fmt.Println("name", nameVal)

// 	countryVal, err := client.Get("country").Result()
// 	if err == redis.Nil {
// 		fmt.Println("no value found")
// 	} else if err != nil {
// 		panic(err)
// 	} else {
// 		fmt.Println("country", countryVal)
// 	}

// 	return nil
// }
// func main() {
// 	// creates a client
// 	client := rClient()

// 	// check connection status
// 	err := ping(client)
// 	if err != nil {
// 		fmt.Println(err)
// 	}

// 	// Using the SET command to set Key-value pair
// 	err = set(client)
// 	if err != nil {
// 		fmt.Println(err)
// 	}

// 	// Using the GET command to get values from keys
// 	err = get(client)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// }
type Object struct {
	Str string
	Num int
}

func mainx() {
	// ring := redis.NewRing(&redis.RingOptions{
	// 	Addrs: map[string]string{
	// 		"server1": ":6379",
	// 		//"server2": ":6380",
	// 	},
	// })

	// mycache := cache.New(&cache.Options{
	// 	Redis:      ring,
	// 	LocalCache: cache.NewTinyLFU(1000, time.Minute),
	// })

	ctx := context.TODO()
	key := "twp"
	// obj := &Object{
	// 	Str: "213525",
	// 	Num: 42,
	// }

	var listStatus []global.StatusDetail
	listStatus = append(listStatus, global.StatusDetail{
		Status: "On",
		Time:   time.Now(),
	},
	)
	if err := global.MyRediscache.Set(&cache.Item{
		Ctx:   ctx,
		Key:   key,
		Value: listStatus,
		TTL:   20 * time.Second,
	}); 
	err != nil {
		panic(err)
	}

	var wanted []global.StatusDetail
	if err := global.MyRediscache.Get(ctx, key, &wanted); err == nil {
		fmt.Println(wanted)
	}

	keye := "index_" + strconv.Itoa(4) + "_" + strconv.Itoa(4)

	fmt.Println(keye)
	// Output: {mystring 42}
}
