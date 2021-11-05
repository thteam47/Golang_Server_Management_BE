package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"example.com/m/global"
	"example.com/m/serverpb"
	gw "example.com/m/serverpb"
	"github.com/dgrijalva/jwt-go"
	"github.com/elastic/go-elasticsearch/esapi"
	"github.com/go-redis/cache/v8"
	"github.com/golang/glog"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/soheilhy/cmux"
	"github.com/tealeg/xlsx"
	"github.com/vigneshuvi/GoDateFormat"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	//"gopkg.in/mgo.v2/bson"
)

type server struct {
	serverpb.UnimplementedServerServiceServer
}

const keySecret = "thteam"

//func
func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
func (s *server) GetUser(ctx context.Context, req *serverpb.InfoUser) (*serverpb.User, error) {
	var idUser string
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser = claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
	}
	var user global.User
	id, _ := primitive.ObjectIDFromHex(idUser)
	collection := global.DB.Collection("user")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := collection.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		log.Fatal(err)
	}
	if user == global.NilUser {
		return nil, fmt.Errorf("Id User not found")
	}
	var action global.Action
	err = global.DB.Collection("action").FindOne(ctx, bson.M{"idUser": id}).Decode(&action)
	if err != nil {
		log.Fatal(err)
	}
	return &serverpb.User{
		IdUser:   user.ID.Hex(),
		FullName: user.FullName,
		Email:    user.Email,
		Username: user.Username,
		Role:     user.Role,
		Action:   action.Action,
	}, nil
}
func (s *server) GetListUser(ctx context.Context, req *serverpb.GetListUser) (*serverpb.ListUser, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser := claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
		if !(claims.Role == "admin") {
			return nil, fmt.Errorf("deny access")
		}
	}
	collection := global.DB.Collection("user")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cur, err := collection.Find(ctx, bson.M{})
	if err != nil {
		log.Fatal(err)
	}
	var ltUser []*serverpb.User
	for cur.Next(context.TODO()) {
		// create a value into which the single document can be decoded
		var elem global.User
		er := cur.Decode(&elem)
		if er != nil {
			log.Fatal(err)
		}
		var action global.Action
		err := global.DB.Collection("action").FindOne(ctx, bson.M{"idUser": elem.ID}).Decode(&action)
		if err != nil {
			log.Fatal(err)
		}
		userResp := &serverpb.User{
			IdUser:   elem.ID.Hex(),
			Username: elem.Username,
			Password: elem.Password,
			Email:    elem.Email,
			Role:     elem.Role,
			FullName: elem.FullName,
			Action:   action.Action,
		}
		ltUser = append(ltUser, userResp)
	}
	return &serverpb.ListUser{
		Data: ltUser,
	}, nil
}
func (s *server) AddUser(ctx context.Context, req *serverpb.User) (*serverpb.User, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser := claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
		if !(claims.Role == "admin") {
			return nil, fmt.Errorf("deny access")
		}
	}
	role := req.GetRole()
	var roleUser string
	if role == "" {
		roleUser = "staff"
	} else {
		roleUser = role
	}
	var actionList []string
	if roleUser == "admin" {
		actionList = append(actionList, "All Rights")
	} else if roleUser == "assistant" {
		actionList = []string{"Add Server", "Update Server", "Detail Status", "Export", "Connect", "Disconnect", "Delete Server", "Change Password"}
	} else {
		actionList = req.GetAction()
	}
	passHash, _ := global.HashPassword(req.GetPassword())

	infoUser := global.User{
		ID:        [12]byte{},
		Username:  req.GetUsername(),
		Password:  passHash,
		FullName:  req.GetFullName(),
		Email:     req.GetEmail(),
		Role:      roleUser,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	insertResult, err := global.DB.Collection("user").InsertOne(ctx, infoUser)
	if err != nil {
		panic(err)
	}
	//action
	action := global.Action{
		ID:     [12]byte{},
		IdUser: insertResult.InsertedID.(primitive.ObjectID),
		Action: actionList,
	}
	_, err = global.DB.Collection("action").InsertOne(ctx, action)
	if err != nil {
		panic(err)
	}
	str := fmt.Sprintf("%v", insertResult.InsertedID)
	idResp := strings.Split(str, "\"")
	resp := &serverpb.User{
		IdUser: idResp[1],
	}
	return resp, nil
}
func (s *server) Logout(ctx context.Context, req *serverpb.Logout) (*serverpb.MessResponse, error) {
	var idUser string
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser = claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
	}
	cache := global.MyRediscache.Delete(ctx, idUser)
	if cache != nil {
		return nil, fmt.Errorf("User logged out")
	}
	return &serverpb.MessResponse{
		Mess: "Done",
	}, nil
}
func (s *server) ChangeActionUser(ctx context.Context, req *serverpb.ChangeActionUser) (*serverpb.MessResponse, error) {
	var idUser string
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser = claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
		if !(claims.Role == "admin") {
			return nil, fmt.Errorf("deny access")
		}
	}
	if idUser == req.GetIdUser() {
		return nil, fmt.Errorf("unachievable")
	}
	role := req.GetRole()
	var roleUser string
	if role == "" {
		roleUser = "staff"
	} else {
		roleUser = role
	}
	var actionList []string
	if roleUser == "admin" {
		actionList = append(actionList, "All Rights")
	} else if roleUser == "assistant" {
		actionList = []string{"Add Server", "Update Server", "Detail Status", "Export", "Connect", "Disconnect", "Delete Server", "Change Password"}
	} else {
		actionList = req.GetAction()
	}
	id, _ := primitive.ObjectIDFromHex(req.GetIdUser())
	filterUser := bson.M{"_id": id}
	updateUser := bson.M{"$set": bson.M{
		"role": roleUser,
	}}
	_, err := global.DB.Collection("user").UpdateOne(ctx, filterUser, updateUser)
	if err != nil {
		log.Fatal(err)
	}
	if !(role == "admin") && !(role == "assistant") {
		filter := bson.M{"idUser": id}
		update := bson.M{"$set": bson.M{
			"action": actionList,
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err = global.DB.Collection("action").UpdateOne(ctx, filter, update)
		if err != nil {
			log.Fatal(err)
		}
	}

	return &serverpb.MessResponse{
		Mess: "Done",
	}, nil
}
func (s *server) UpdateUser(ctx context.Context, req *serverpb.ChangeUser) (*serverpb.UserResponse, error) {
	var idUser string
	var role string
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser = claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
		role = claims.Role
	}
	var id primitive.ObjectID
	if req.GetIdUser() == "null" {
		id, _ = primitive.ObjectIDFromHex(idUser)
	} else {
		if !(role == "admin") {
			return nil, fmt.Errorf("deny access")
		}
		id, _ = primitive.ObjectIDFromHex(req.GetIdUser())
	}

	filterUser := bson.M{"_id": id}
	updateUser := bson.M{"$set": bson.M{
		"fullname": req.GetData().GetFullName(),
		"username": req.GetData().GetUsername(),
		"email":    req.GetData().GetEmail(),
	}}
	_, err := global.DB.Collection("user").UpdateOne(ctx, filterUser, updateUser)
	if err != nil {
		log.Fatal(err)
	}
	return &serverpb.UserResponse{
		IdUser: idUser,
		Data: &serverpb.User{
			Username: req.GetData().Username,
			FullName: req.GetData().FullName,
			Email:    req.GetData().Email,
		},
	}, nil
}
func (s *server) ChangePassUser(ctx context.Context, req *serverpb.ChangePasswordUser) (*serverpb.MessResponse, error) {
	var role string
	var idUser string
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser = claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
		role = claims.Role
	}
	var id primitive.ObjectID
	if req.GetIdUser() == "null" {
		id, _ = primitive.ObjectIDFromHex(idUser)
	} else {
		if !(role == "admin") {
			return nil, fmt.Errorf("deny access")
		}
		id, _ = primitive.ObjectIDFromHex(req.GetIdUser())
	}
	passHash, _ := global.HashPassword(req.GetPassword())
	filterUser := bson.M{"_id": id}
	updateUser := bson.M{"$set": bson.M{
		"password": passHash,
	}}
	_, err := global.DB.Collection("user").UpdateOne(ctx, filterUser, updateUser)
	if err != nil {
		log.Fatal(err)
	}
	return &serverpb.MessResponse{
		Mess: "Done",
	}, nil
}
func (s *server) DeleteUser(ctx context.Context, req *serverpb.DeleteUser) (*serverpb.MessResponse, error) {
	var idUser string
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser = claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
		if !(claims.Role == "admin") {
			return nil, fmt.Errorf("deny access")
		}
	}
	if idUser == req.GetIdUser() {
		return nil, fmt.Errorf("unachievable")
	}
	id, _ := primitive.ObjectIDFromHex(req.GetIdUser())
	result, err := global.DB.Collection("user").DeleteOne(ctx, bson.M{"_id": id})

	if err != nil {
		log.Fatal(err)
	}
	if result.DeletedCount == 0 {
		return nil, errors.New("Id incorrect")
	}
	_, err = global.DB.Collection("action").DeleteOne(ctx, bson.M{"idUser": id})
	if err != nil {
		log.Fatal(err)
	}
	return &serverpb.MessResponse{
		Mess: "Done",
	}, nil
}
func (s *server) Login(ctx context.Context, req *serverpb.LoginServer) (*serverpb.ResultLogin, error) {
	username, password := req.GetUsername(), req.GetPassword()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var user global.User
	global.DB.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if user == global.NilUser {
		resp := &serverpb.ResultLogin{
			Ok:          false,
			AccessToken: "",
		}
		return resp, errors.New("User not found")
	}
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		resp := &serverpb.ResultLogin{
			Ok:          false,
			AccessToken: "",
		}
		return resp, errors.New("Incorrect password")
	}
	expirationTime := time.Now().Add(30 * time.Minute)
	claims := &global.Claims{
		Role: user.Role,
		StandardClaims: jwt.StandardClaims{
			Issuer:    user.ID.Hex(),
			ExpiresAt: expirationTime.Unix(),
		},
	}
	claim := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := claim.SignedString([]byte(keySecret))
	if err != nil {
		resp := &serverpb.ResultLogin{
			Ok:          false,
			AccessToken: "",
		}
		return resp, errors.New("Could not login")
	}
	if err := global.MyRediscache.Set(&cache.Item{
		Ctx:   ctx,
		Key:   user.ID.Hex(),
		Value: token,
		TTL:   30 * time.Minute,
	}); err != nil {
		panic(err)
	}

	resp := &serverpb.ResultLogin{
		Ok:          true,
		AccessToken: token,
		Role:        user.Role,
	}
	return resp, nil
}

func (s *server) Connect(ctx context.Context, req *serverpb.LoginServer) (*serverpb.MessResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser := claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
		if !(claims.Role == "admin") && !(claims.Role == "assistant") {
			var action global.Action
			var listAction []string
			idU, _ := primitive.ObjectIDFromHex(idUser)
			global.DB.Collection("action").FindOne(ctx, bson.M{"idUser": idU}).Decode(&action)
			listAction = action.Action

			if listAction == nil || !stringInSlice("Connect", listAction) {
				return nil, fmt.Errorf("deny access")
			}
		}
	}
	username, password := req.GetUsername(), req.GetPassword()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var elem global.InfoServer
	collection := global.DB.Collection("servertest")
	collection.FindOne(ctx, bson.M{"username": username, "password": password}).Decode(&elem)
	if elem == global.NilServer {
		return nil, errors.New("Username or password incorrect")
	}
	if elem != global.NilServer {
		var r map[string]interface{}
		var buf bytes.Buffer
		query := map[string]interface{}{
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"_id": elem.ID.Hex(),
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Fatalf("Error encoding query: %s", err)
		}
		res, err := global.DBels.Search(
			global.DBels.Search.WithContext(context.Background()),
			global.DBels.Search.WithIndex("server-elastest"),
			global.DBels.Search.WithBody(&buf),
			global.DBels.Search.WithTrackTotalHits(true),
			global.DBels.Search.WithPretty(),
		)
		if err != nil {
			log.Fatalf("Error getting response: %s", err)
		}
		if !res.IsError() {
			defer res.Body.Close()
			if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
				log.Fatalf("Error parsing the response body: %s", err)
			}

			var detailSV global.ListStatus
			for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {
				m, _ := json.Marshal(hit.(map[string]interface{})["_source"])
				err := json.Unmarshal(m, &detailSV)
				if err != nil {
					log.Fatalf("Error getting response: %s", err)
				}
			}
			detailSV.ChangeStatus = append(detailSV.ChangeStatus, global.StatusDetail{
				Status: "On",
				Time:   time.Now(),
			},
			)
			info := &global.ListStatus{
				ChangeStatus: detailSV.ChangeStatus,
			}
			var inInterface map[string]interface{}
			inter, _ := json.Marshal(info)
			json.Unmarshal(inter, &inInterface)
			var buf bytes.Buffer
			doc := map[string]interface{}{
				"query": map[string]interface{}{
					"match": map[string]interface{}{
						"_id": elem.ID.Hex(),
					},
				},
				"script": map[string]interface{}{
					"source": "ctx._source.changeStatus=params.changeStatus;",
					"params": inInterface,
				},
			}
			if err := json.NewEncoder(&buf).Encode(doc); err != nil {
				log.Fatalf("Error update: %s", err)
			}
			res, err := global.DBels.UpdateByQuery(
				[]string{"server-elastest"},
				global.DBels.UpdateByQuery.WithBody(&buf),
				global.DBels.UpdateByQuery.WithContext(context.Background()),
				global.DBels.UpdateByQuery.WithPretty(),
			)
			if err != nil {
				log.Fatalf("Error update: %s", err)
			}
			defer res.Body.Close()
		}

	} else {
		return nil, errors.New("Id incorrect")
	}
	RemoveCache("indexCache")
	RemoveCache("statusCache")
	return &serverpb.MessResponse{
		Mess: "Done",
	}, nil
}

func (s *server) CheckServerName(ctx context.Context, req *serverpb.CheckServerNameRequest) (*serverpb.CheckServerNameResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser := claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}

	}
	servername := req.GetServerName()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var elem global.InfoServer
	collection := global.DB.Collection("servertest")
	collection.FindOne(ctx, bson.M{"servername": servername}).Decode(&elem)
	if elem == global.NilServer {
		return &serverpb.CheckServerNameResponse{
			Check: false,
		}, nil
	}
	return &serverpb.CheckServerNameResponse{
		Check: true,
	}, nil
}
func (s *server) Search(ctx context.Context, req *serverpb.SearchRequest) (*serverpb.ListServer, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser := claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}

	}
	var limit int64 = req.GetLimitPage()
	var page int64 = req.GetNumberPage()
	var dt []*serverpb.Server
	var totalSer int64
	field := req.GetFieldSearch()
	filter := bson.M{
		field: bson.M{
			"$regex": primitive.Regex{
				Pattern: req.GetKeySearch(),
				Options: "i",
			},
		},
	}

	collection := global.DB.Collection("servertest")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	findOptions := options.Find()
	if page == 1 {
		findOptions.SetSkip(0)
		findOptions.SetLimit(limit)
	} else {
		findOptions.SetSkip((page - 1) * limit)
		findOptions.SetLimit(limit)
	}
	findOptions.SetSort(bson.M{"created_at": -1})
	cur, err := collection.Find(ctx, filter, findOptions)
	if err != nil {
		log.Fatal(err)
	}
	curTotal, err := collection.Find(ctx, filter)
	if err != nil {
		log.Fatal(err)
	}
	totalSer = int64(curTotal.RemainingBatchLength())
	var st []global.InfoServer
	for cur.Next(context.TODO()) {
		// create a value into which the single document can be decoded
		var elem global.InfoServer
		er := cur.Decode(&elem)
		if er != nil {
			log.Fatal(err)
		}
		st = append(st, elem)
		if st == nil {
			return &serverpb.ListServer{
				Data: dt,
			}, nil
		}
	}
	for _, v := range st {
		var status string
		var r map[string]interface{}
		var buf bytes.Buffer
		query := map[string]interface{}{
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"_id": v.ID.Hex(),
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Fatalf("Error encoding query: %s", err)
		}
		res, err := global.DBels.Search(
			global.DBels.Search.WithContext(context.Background()),
			global.DBels.Search.WithIndex("server-elastest"),
			global.DBels.Search.WithBody(&buf),
			global.DBels.Search.WithTrackTotalHits(true),
			global.DBels.Search.WithPretty(),
		)
		if err != nil {
			log.Fatalf("Error getting response: %s", err)
		}
		defer res.Body.Close()
		if !res.IsError() {
			if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
				log.Fatalf("Error parsing the response body: %s", err)
			}
			if r != nil {
				var detailSV global.ListStatus
				for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {
					m, _ := json.Marshal(hit.(map[string]interface{})["_source"])
					err := json.Unmarshal(m, &detailSV)
					if err != nil {
						log.Fatalf("Error getting response: %s", err)
					}
				}
				if len(detailSV.ChangeStatus) > 0 {
					status = detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status
				}
			}
		}
		dt = append(dt, &serverpb.Server{
			IdServer:    v.ID.Hex(),
			Username:    v.Username,
			ServerName:  v.ServerName,
			Ip:          v.Ip,
			Password:    v.Password,
			Description: v.Description,
			Status:      status,
		})
	}
	return &serverpb.ListServer{
		Data:        dt,
		TotalServer: totalSer,
	}, nil
}
func (s *server) Disconnect(ctx context.Context, req *serverpb.Disconnect) (*serverpb.MessResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser := claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
		if !(claims.Role == "admin") && !(claims.Role == "assistant") {
			var action global.Action
			var listAction []string
			idU, _ := primitive.ObjectIDFromHex(idUser)
			global.DB.Collection("action").FindOne(ctx, bson.M{"idUser": idU}).Decode(&action)
			listAction = action.Action
			if listAction == nil || !stringInSlice("Disconnect", listAction) {
				return nil, fmt.Errorf("deny access")
			}
		}
	}
	id, _ := primitive.ObjectIDFromHex(req.GetIdServer())
	collection := global.DB.Collection("servertest")
	var elem global.InfoServer
	err := collection.FindOne(ctx, bson.M{"_id": id}).Decode(&elem)
	if err != nil {
		log.Fatal(err)
	}
	if elem != global.NilServer {
		var r map[string]interface{}
		var buf bytes.Buffer
		query := map[string]interface{}{
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"_id": elem.ID.Hex(),
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Fatalf("Error encoding query: %s", err)
		}
		res, err := global.DBels.Search(
			global.DBels.Search.WithContext(context.Background()),
			global.DBels.Search.WithIndex("server-elastest"),
			global.DBels.Search.WithBody(&buf),
			global.DBels.Search.WithTrackTotalHits(true),
			global.DBels.Search.WithPretty(),
		)
		if err != nil {
			log.Fatalf("Error getting response: %s", err)
		}
		if !res.IsError() {
			defer res.Body.Close()
			if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
				log.Fatalf("Error parsing the response body: %s", err)
			}

			var detailSV global.ListStatus
			for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {
				m, _ := json.Marshal(hit.(map[string]interface{})["_source"])
				err := json.Unmarshal(m, &detailSV)
				if err != nil {
					log.Fatalf("Error getting response: %s", err)
				}
			}
			detailSV.ChangeStatus = append(detailSV.ChangeStatus, global.StatusDetail{
				Status: "Off",
				Time:   time.Now(),
			},
			)
			info := &global.ListStatus{
				ChangeStatus: detailSV.ChangeStatus,
			}
			var inInterface map[string]interface{}
			inter, _ := json.Marshal(info)
			json.Unmarshal(inter, &inInterface)
			var buf bytes.Buffer
			doc := map[string]interface{}{
				"query": map[string]interface{}{
					"match": map[string]interface{}{
						"_id": elem.ID.Hex(),
					},
				},
				"script": map[string]interface{}{
					"source": "ctx._source.changeStatus=params.changeStatus;",
					"params": inInterface,
				},
			}
			if err := json.NewEncoder(&buf).Encode(doc); err != nil {
				log.Fatalf("Error update: %s", err)
			}
			res, err := global.DBels.UpdateByQuery(
				[]string{"server-elastest"},
				global.DBels.UpdateByQuery.WithBody(&buf),
				global.DBels.UpdateByQuery.WithContext(context.Background()),
				global.DBels.UpdateByQuery.WithPretty(),
			)
			if err != nil {
				log.Fatalf("Error update: %s", err)
			}
			defer res.Body.Close()
		}
	} else {
		return nil, errors.New("Id incorrect")
	}
	RemoveCache("indexCache")
	RemoveCache("statusCache")
	return &serverpb.MessResponse{
		Mess: "Done",
	}, nil
}

func (s *server) Index(ctx context.Context, req *serverpb.PaginationRequest) (*serverpb.ListServer, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser := claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil {
			return nil, fmt.Errorf("token invalid")
		}
	}

	var limit int64 = req.GetLimitPage()
	var page int64 = req.GetNumberPage()

	key := "index_" + strconv.FormatInt(limit, 10) + "_" + strconv.FormatInt(page, 10)
	keyTotal := "totalServer_" + strconv.FormatInt(limit, 10) + "_" + strconv.FormatInt(page, 10)
	var dt []*serverpb.Server
	var totalSer int64
	data := global.MyRediscache.Get(ctx, key, &dt)
	totalSe := global.MyRediscache.Get(ctx, keyTotal, &totalSer)

	if data == nil && totalSe == nil {
		return &serverpb.ListServer{
			Data:        dt,
			TotalServer: totalSer,
		}, nil
	} else {
		collection := global.DB.Collection("servertest")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		findOptions := options.Find()
		findOptions.SetSort(bson.M{"created_at": -1})
		if page == 1 {
			findOptions.SetSkip(0)
			findOptions.SetLimit(limit)
		} else {
			findOptions.SetSkip((page - 1) * limit)
			findOptions.SetLimit(limit)
		}

		cur, err := collection.Find(ctx, bson.M{}, findOptions)
		if err != nil {
			log.Fatal(err)
		}
		curTotal, err := collection.Find(ctx, bson.M{})
		if err != nil {
			log.Fatal(err)
		}
		totalSer = int64(curTotal.RemainingBatchLength())
		var st []global.InfoServer
		for cur.Next(context.TODO()) {
			// create a value into which the single document can be decoded
			var elem global.InfoServer
			er := cur.Decode(&elem)
			if er != nil {
				log.Fatal(err)
			}
			st = append(st, elem)
			if st == nil {
				return &serverpb.ListServer{
					Data: dt,
				}, nil
			}
		}
		for _, v := range st {
			var status string
			var r map[string]interface{}
			var buf bytes.Buffer
			query := map[string]interface{}{
				"query": map[string]interface{}{
					"match": map[string]interface{}{
						"_id": v.ID.Hex(),
					},
				},
			}
			if err := json.NewEncoder(&buf).Encode(query); err != nil {
				log.Fatalf("Error encoding query: %s", err)
			}
			res, err := global.DBels.Search(
				global.DBels.Search.WithContext(context.Background()),
				global.DBels.Search.WithIndex("server-elastest"),
				global.DBels.Search.WithBody(&buf),
				global.DBels.Search.WithTrackTotalHits(true),
				global.DBels.Search.WithPretty(),
			)
			if err != nil {
				log.Fatalf("Error getting response: %s", err)
			}
			defer res.Body.Close()
			if !res.IsError() {
				if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
					log.Fatalf("Error parsing the response body: %s", err)
				}
				if r != nil {
					var detailSV global.ListStatus
					for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {
						m, _ := json.Marshal(hit.(map[string]interface{})["_source"])
						err := json.Unmarshal(m, &detailSV)
						if err != nil {
							log.Fatalf("Error getting response: %s", err)
						}
					}
					if len(detailSV.ChangeStatus) > 0 {
						status = detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status
					}
				}
			}
			dt = append(dt, &serverpb.Server{
				IdServer:    v.ID.Hex(),
				Username:    v.Username,
				ServerName:  v.ServerName,
				Ip:          v.Ip,
				Password:    v.Password,
				Description: v.Description,
				Status:      status,
			})
		}
	}

	if err := global.MyRediscache.Set(&cache.Item{
		Ctx:   ctx,
		Key:   key,
		Value: dt,
	}); err != nil {
		panic(err)
	}
	if err := global.MyRediscache.Set(&cache.Item{
		Ctx:   ctx,
		Key:   keyTotal,
		Value: totalSer,
	}); err != nil {
		panic(err)
	}
	indexKeyCache := "indexCache"

	SetCache(key, indexKeyCache)
	SetCache(keyTotal, indexKeyCache)

	resp := &serverpb.ListServer{
		Data:        dt,
		TotalServer: totalSer,
	}
	return resp, nil
}
func (s *server) AddServer(ctx context.Context, req *serverpb.Server) (*serverpb.ResponseServer, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser := claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
		if !(claims.Role == "admin") && !(claims.Role == "assistant") {
			var action global.Action
			var listAction []string
			idU, _ := primitive.ObjectIDFromHex(idUser)
			global.DB.Collection("action").FindOne(ctx, bson.M{"idUser": idU}).Decode(&action)
			listAction = action.Action
			if listAction == nil || !stringInSlice("Add Server", listAction) {
				return nil, fmt.Errorf("deny access")
			}
		}
	}

	var listStatus []global.StatusDetail
	listStatus = append(listStatus, global.StatusDetail{
		Status: "On",
		Time:   time.Now(),
	},
	)
	infoSv := global.InfoServer{
		ID:          [12]byte{},
		Username:    req.GetUsername(),
		Password:    string(req.GetPassword()),
		ServerName:  req.GetServerName(),
		Ip:          req.GetIp(),
		Description: req.GetDescription(),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	insertResult, err := global.DB.Collection("servertest").InsertOne(ctx, infoSv)
	if err != nil {
		panic(err)
	}
	//elasticsearch

	str := fmt.Sprintf("%v", insertResult.InsertedID)
	idResp := strings.Split(str, "\"")

	info := &global.ListStatus{
		ChangeStatus: listStatus,
	}
	//res, err := global.DBels.Info()
	dataJSON, err := json.Marshal(info)
	//js := string(dataJSON)
	//defer wg.Done()
	res := esapi.IndexRequest{
		Index:      "server-elastest",
		DocumentID: idResp[1],
		Body:       strings.NewReader(string(dataJSON)),
	}
	res.Do(context.Background(), &global.DBels)
	resp := &serverpb.ResponseServer{
		IdServer: idResp[1],
		Data: &serverpb.Server{
			Username:    infoSv.Username,
			ServerName:  infoSv.ServerName,
			Password:    infoSv.Password,
			Ip:          infoSv.Ip,
			Description: infoSv.Description,
		},
	}
	RemoveCache("indexCache")
	RemoveCache("statusCache")
	return resp, nil
}
func RemoveCache(keyListCache string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var keyIndex []string
	keyCacheIndex := global.MyRediscache.Get(ctx, keyListCache, &keyIndex)
	if keyCacheIndex == nil {
		for _, key := range keyIndex {
			global.MyRediscache.Delete(ctx, key)
		}
	}
}
func (s *server) UpdateServer(ctx context.Context, req *serverpb.UpdateRequest) (*serverpb.ResponseServer, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser := claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
		if !(claims.Role == "admin") && !(claims.Role == "assistant") {
			var action global.Action
			var listAction []string
			idU, _ := primitive.ObjectIDFromHex(idUser)
			global.DB.Collection("action").FindOne(ctx, bson.M{"idUser": idU}).Decode(&action)
			listAction = action.Action
			if listAction == nil || !stringInSlice("Update Server", listAction) {
				return nil, fmt.Errorf("deny access")
			}
		}
	}
	id, _ := primitive.ObjectIDFromHex(req.GetIdServer())
	filter := bson.M{"_id": id}
	update := bson.M{"$set": bson.M{
		"username":    req.GetInfoServer().GetUsername(),
		"ip":          req.GetInfoServer().GetIp(),
		"servername":  req.GetInfoServer().GetServerName(),
		"description": req.GetInfoServer().GetDescription(),
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := global.DB.Collection("servertest").UpdateOne(ctx, filter, update)
	if err != nil {
		log.Fatal(err)
	}
	resp := &serverpb.ResponseServer{
		IdServer: req.GetIdServer(),
		Data: &serverpb.Server{
			Username:    req.GetInfoServer().GetUsername(),
			ServerName:  req.GetInfoServer().GetServerName(),
			Ip:          req.GetInfoServer().GetIp(),
			Description: req.GetInfoServer().GetDescription(),
		},
	}
	RemoveCache("indexCache")
	RemoveCache("statusCache")
	return resp, nil
}
func (s *server) DetailsServer(ctx context.Context, req *serverpb.DetailsServer) (*serverpb.DetailsServerResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser := claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
		idUserPri, _ := primitive.ObjectIDFromHex(idUser)
		if !(claims.Role == "admin") && !(claims.Role == "assistant") {
			var action global.Action
			var listAction []string
			global.DB.Collection("action").FindOne(ctx, bson.M{"idUser": idUserPri}).Decode(&action)
			listAction = action.Action
			if listAction == nil || !stringInSlice("Detail Status", listAction) {
				return nil, fmt.Errorf("deny access")
			}
		}
	}
	if req.GetIdServer() == "" {
		return nil, errors.New("Idserver not found")
	}
	id, _ := primitive.ObjectIDFromHex(req.GetIdServer())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	keyList := "details_statusList_" + id.Hex() + req.GetTimeIn() + req.GetTimeOut()
	keyStatus := "details_status_" + id.Hex() + req.GetTimeIn() + req.GetTimeOut()
	var statusList []*serverpb.StatusDetail
	var statusServer string
	var detailSV global.ListStatus
	dataList := global.MyRediscache.Get(ctx, keyList, &statusList)
	dataStatus := global.MyRediscache.Get(ctx, keyStatus, &statusServer)
	if dataList != nil && dataStatus != nil {
		//search
		var r map[string]interface{}
		var buf bytes.Buffer
		query := map[string]interface{}{
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"_id": id,
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Fatalf("Error encoding query: %s", err)
		}
		res, err := global.DBels.Search(
			global.DBels.Search.WithContext(context.Background()),
			global.DBels.Search.WithIndex("server-elastest"),
			global.DBels.Search.WithBody(&buf),
			global.DBels.Search.WithTrackTotalHits(true),
			global.DBels.Search.WithPretty(),
		)
		if err != nil {
			log.Fatalf("Error getting response: %s", err)
		}
		defer res.Body.Close()
		if !res.IsError() {
			if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
				log.Fatalf("Error parsing the response body: %s", err)
			}
			for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {
				m, _ := json.Marshal(hit.(map[string]interface{})["_source"])
				err := json.Unmarshal(m, &detailSV)
				if err != nil {
					log.Fatalf("Error getting response: %s", err)
				}
			}
			if len(detailSV.ChangeStatus) == 0 {
				return nil, errors.New("Idserver not found")
			}
			var start time.Time
			var end time.Time
			if req.GetTimeIn() == "" {
				start = detailSV.ChangeStatus[0].Time
			} else {
				startTT, err := time.Parse(time.RFC3339, req.GetTimeIn()+"+07:00")
				if err != nil {
					log.Fatalf("error start")
				}
				if startTT.Before(detailSV.ChangeStatus[0].Time) == true {
					start = detailSV.ChangeStatus[0].Time
				} else {
					start = startTT
				}
			}
			if req.GetTimeOut() == "" {
				end = time.Now()
			} else {
				endTT, err := time.Parse(time.RFC3339, req.GetTimeOut()+"+07:00")
				if err != nil {
					log.Fatalf("error end")
				}
				if endTT.After(time.Now()) == true {
					end = time.Now()
				} else {
					end = endTT
				}
			}

			for i := 0; i < len(detailSV.ChangeStatus); i++ {
				tmp := detailSV.ChangeStatus[i].Time
				if tmp.Before(detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Time) {
					if tmp.Before(start) && detailSV.ChangeStatus[i+1].Time.After(start) {
						statusList = append(statusList, &serverpb.StatusDetail{
							StatusDt: detailSV.ChangeStatus[i].Status,
							Time:     start.Format(time.RFC3339),
						})
					}
				}
				if tmp.After(start) && tmp.Before(end) || tmp == start || tmp == end {
					statusList = append(statusList, &serverpb.StatusDetail{
						StatusDt: detailSV.ChangeStatus[i].Status,
						Time:     detailSV.ChangeStatus[i].Time.Format(time.RFC3339),
					})
				}
				if tmp.Before(detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Time) {
					if tmp.Before(end) && detailSV.ChangeStatus[i+1].Time.After(end) {
						statusList = append(statusList, &serverpb.StatusDetail{
							StatusDt: detailSV.ChangeStatus[i].Status,
							Time:     end.Format(time.RFC3339),
						})
					}
				}
			}
			if end.After(detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Time) {
				statusList = append(statusList, &serverpb.StatusDetail{
					StatusDt: detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status,
					Time:     end.Format(time.RFC3339),
				})
			}

			if err := global.MyRediscache.Set(&cache.Item{
				Ctx:   ctx,
				Key:   keyList,
				Value: statusList,
			}); err != nil {
				panic(err)
			}
		}
		statusServer = detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status
		if err := global.MyRediscache.Set(&cache.Item{
			Ctx:   ctx,
			Key:   keyStatus,
			Value: statusServer,
		}); err != nil {
			panic(err)
		}
	}
	SetCache(keyList, "statusCache")
	SetCache(keyStatus, "statusCache")

	resp := &serverpb.DetailsServerResponse{
		StatusServer: statusServer,
		Status:       statusList,
	}
	return resp, nil
}
func SetCache(key string, listCache string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	keyCache := listCache
	var keyList []string
	keyCacheStatus := global.MyRediscache.Get(ctx, keyCache, &keyList)
	if keyCacheStatus != nil {
		keyList = append(keyList, key)
	} else {
		if !stringInSlice(key, keyList) {
			keyList = append(keyList, key)
		}
	}

	if err := global.MyRediscache.Set(&cache.Item{
		Ctx:   ctx,
		Key:   keyCache,
		Value: keyList,
	}); err != nil {
		panic(err)
	}
}
func (s *server) Export(ctx context.Context, req *serverpb.ExportRequest) (*serverpb.ExportResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser := claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
		if !(claims.Role == "admin") && !(claims.Role == "assistant") {
			var action global.Action
			var listAction []string
			idU, _ := primitive.ObjectIDFromHex(idUser)
			global.DB.Collection("action").FindOne(ctx, bson.M{"idUser": idU}).Decode(&action)
			listAction = action.Action
			if listAction == nil || !stringInSlice("Export", listAction) {
				return nil, fmt.Errorf("deny access")
			}
		}
	}
	file := xlsx.NewFile()
	date := time.Now().Format(GoDateFormat.ConvertFormat("yyyy-MMM-dd-hh-MM-ss"))
	sheet, _ := file.AddSheet("ServerManagement")
	row := sheet.AddRow()
	colName := [6]string{"Server name", "Username", "Password", "Ip", "Description", "Status"}
	for i := 0; i < len(colName); i++ {
		cell := row.AddCell()
		cell.Value = colName[i]
	}
	collection := global.DB.Collection("servertest")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var cur *mongo.Cursor
	var err error
	if req.GetPage() == false {
		cur, err = collection.Find(ctx, bson.M{})
	} else {
		page := req.GetNumberPage()
		limit := req.GetLimitPage()
		findOptions := options.Find()
		findOptions.SetSort(bson.M{"created_at": -1})
		if page == 1 {
			findOptions.SetSkip(0)
			findOptions.SetLimit(limit)
		} else {
			findOptions.SetSkip((page - 1) * limit)
			findOptions.SetLimit(limit)
		}
		cur, err = collection.Find(ctx, bson.M{}, findOptions)
	}
	if err != nil {
		log.Fatal(err)
	}
	for cur.Next(context.TODO()) {
		// create a value into which the single document can be decoded
		row = sheet.AddRow()
		var elem global.InfoServer
		er := cur.Decode(&elem)
		if er != nil {
			log.Fatal(err)
		}
		listStatus := ""
		//search
		var r map[string]interface{}
		var buf bytes.Buffer
		query := map[string]interface{}{
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"_id": elem.ID.Hex(),
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Fatalf("Error encoding query: %s", err)
		}
		res, err := global.DBels.Search(
			global.DBels.Search.WithContext(context.Background()),
			global.DBels.Search.WithIndex("server-elastest"),
			global.DBels.Search.WithBody(&buf),
			global.DBels.Search.WithTrackTotalHits(true),
			global.DBels.Search.WithPretty(),
		)
		if err != nil {
			log.Fatalf("Error getting response: %s", err)
		}
		defer res.Body.Close()
		if !res.IsError() {
			if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
				log.Fatalf("Error parsing the response body: %s", err)
			}
			var detailSV global.ListStatus
			for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {
				m, _ := json.Marshal(hit.(map[string]interface{})["_source"])
				err := json.Unmarshal(m, &detailSV)
				if err != nil {
					log.Fatalf("Error getting response: %s", err)
				}
			}

			listStatus = detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Time.String() + ": " + detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status
			result := [6]string{elem.ServerName, elem.Username, elem.Password, elem.Ip, elem.Description, listStatus}
			for i := 0; i < len(colName); i++ {
				cell := row.AddCell()
				cell.Value = result[i]
			}
		}
	}
	host, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	os.Setenv("DB_HOST", host)
	fileName := "swaggerui/export/" + date + ".xlsx"

	err = file.Save(fileName)
	if err != nil {
		log.Fatalf("Error getting response: %s", err)
	}
	os.Setenv("FILENAME", fileName)
	return &serverpb.ExportResponse{
		Url: os.ExpandEnv("$DB_HOST:9090/$FILENAME"),
	}, nil
}
func (s *server) DeleteServer(ctx context.Context, req *serverpb.DelServer) (*serverpb.DeleteServerResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser := claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
		if !(claims.Role == "admin") && !(claims.Role == "assistant") {
			var action global.Action
			var listAction []string
			idU, _ := primitive.ObjectIDFromHex(idUser)
			global.DB.Collection("action").FindOne(ctx, bson.M{"idUser": idU}).Decode(&action)
			listAction = action.Action
			if listAction == nil || !stringInSlice("Delete Server", listAction) {
				return nil, fmt.Errorf("deny access")
			}
		}
	}
	id, _ := primitive.ObjectIDFromHex(req.GetIdServer())
	result, err := global.DB.Collection("servertest").DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		log.Fatal(err)
	}
	if result.DeletedCount == 0 {
		return &serverpb.DeleteServerResponse{
			Ok: false,
		}, errors.New("Id incorrect")
	}

	res := esapi.DeleteRequest{
		Index:      "server-elastest",
		DocumentID: req.IdServer,
	}
	_, err = res.Do(context.Background(), &global.DBels)
	if err != nil {
		log.Fatalf("Error getting response: %s", err)
	}
	RemoveCache("indexCache")
	RemoveCache("statusCache")
	resp := &serverpb.DeleteServerResponse{
		Ok: true,
	}
	return resp, nil
}
func UpdateStatus() {
	for {
		collection := global.DB.Collection("servertest")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cur, err := collection.Find(ctx, bson.M{})
		if err != nil {
			log.Fatal(err)
		}
		if cur != nil {
			for cur.Next(context.TODO()) {
				// create a value into which the single document can be decoded
				var elem global.InfoServer
				er := cur.Decode(&elem)
				if er != nil {
					log.Fatal(err)
				}
				//get list status
				var r map[string]interface{}
				var buf bytes.Buffer
				query := map[string]interface{}{
					"query": map[string]interface{}{
						"match": map[string]interface{}{
							"_id": elem.ID.Hex(),
						},
					},
				}
				if err := json.NewEncoder(&buf).Encode(query); err != nil {
					log.Fatalf("Error encoding query: %s", err)
				}
				res, err := global.DBels.Search(
					global.DBels.Search.WithContext(context.Background()),
					global.DBels.Search.WithIndex("server-elastest"),
					global.DBels.Search.WithBody(&buf),
					global.DBels.Search.WithTrackTotalHits(true),
					global.DBels.Search.WithPretty(),
				)
				if err != nil {
					log.Fatalf("Error getting response: %s", err)
				}
				if !res.IsError() {
					defer res.Body.Close()
					if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
						log.Fatalf("Error parsing the response body: %s", err)
					}

					var detailSV global.ListStatus
					for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {
						m, _ := json.Marshal(hit.(map[string]interface{})["_source"])
						err := json.Unmarshal(m, &detailSV)
						if err != nil {
							log.Fatalf("Error getting response: %s", err)
						}
					}
					dayChange := time.Now().Sub(elem.UpdatedAt).Hours() / 24
					if dayChange > 60 {
						if detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status != "Invalid" {
							detailSV.ChangeStatus = append(detailSV.ChangeStatus, global.StatusDetail{
								Status: "Invalid",
								Time:   time.Now(),
							},
							)
							info := &global.ListStatus{
								ChangeStatus: detailSV.ChangeStatus,
							}
							var inInterface map[string]interface{}
							inrec, _ := json.Marshal(info)
							json.Unmarshal(inrec, &inInterface)
							var buf bytes.Buffer
							doc := map[string]interface{}{
								"query": map[string]interface{}{
									"match": map[string]interface{}{
										"_id": elem.ID.Hex(),
									},
								},
								"script": map[string]interface{}{
									"source": "ctx._source.changeStatus=params.changeStatus;",
									"params": inInterface,
								},
							}
							if err := json.NewEncoder(&buf).Encode(doc); err != nil {
								log.Fatalf("Error update: %s", err)
							}
							res, err := global.DBels.UpdateByQuery(
								[]string{"server-elastest"},
								global.DBels.UpdateByQuery.WithBody(&buf),
								global.DBels.UpdateByQuery.WithContext(context.Background()),
								global.DBels.UpdateByQuery.WithPretty(),
							)
							if err != nil {
								log.Fatalf("Error update: %s", err)
							}
							defer res.Body.Close()
						}
					}
				}
			}
		}
		time.Sleep(1 * time.Hour)
	}
}

func (s *server) ChangePassword(ctx context.Context, req *serverpb.ChangePasswordRequest) (*serverpb.MessResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("No data request")
	}
	var authorization []string
	authorization = md["authorization"]
	if len(authorization) < 1 {
		return nil, fmt.Errorf("no authorization")
	} else {
		token := strings.TrimPrefix(authorization[0], "Bearer ")
		if token == "undefined" {
			return nil, fmt.Errorf("no authorization")
		}
		claims := &global.Claims{}
		playload, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("un")
			}
			return []byte(keySecret), nil
		},
		)
		if err != nil {
			return nil, fmt.Errorf("token incorrect")
		}
		if !playload.Valid {
			return nil, fmt.Errorf("token invalid")
		}
		idUser := claims.Issuer
		var tokenCache string
		checkToken := global.MyRediscache.Get(ctx, idUser, &tokenCache)
		if checkToken != nil && tokenCache != idUser {
			return nil, fmt.Errorf("token invalid")
		}
		if !(claims.Role == "admin") && !(claims.Role == "assistant") {
			var action global.Action
			var listAction []string
			idU, _ := primitive.ObjectIDFromHex(idUser)
			global.DB.Collection("action").FindOne(ctx, bson.M{"idUser": idU}).Decode(&action)
			listAction = action.Action
			if listAction == nil || !stringInSlice("Change Password", listAction) {
				return nil, fmt.Errorf("deny access")
			}
		}
	}
	id, _ := primitive.ObjectIDFromHex(req.GetIdServer())

	var sv global.InfoServer
	global.DB.Collection("servertest").FindOne(ctx, bson.M{"_id": id}).Decode(&sv)
	var r map[string]interface{}
	var buf bytes.Buffer
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"match": map[string]interface{}{
				"_id": req.GetIdServer(),
			},
		},
	}

	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		log.Fatalf("Error encoding query: %s", err)
	}
	res, err := global.DBels.Search(
		global.DBels.Search.WithContext(context.Background()),
		global.DBels.Search.WithIndex("server-elastest"),
		global.DBels.Search.WithBody(&buf),
		global.DBels.Search.WithTrackTotalHits(true),
		global.DBels.Search.WithPretty(),
	)
	if !res.IsError() {
		if err != nil {
			log.Fatalf("Error getting response: %s", err)
		}
		defer res.Body.Close()
		if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
			log.Fatalf("Error parsing the response body: %s", err)
		}
		var detailSV global.ListStatus
		for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {
			m, _ := json.Marshal(hit.(map[string]interface{})["_source"])
			err := json.Unmarshal(m, &detailSV)
			if err != nil {
				log.Fatalf("Error getting response: %s", err)
			}
		}
		if detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status == "Invalid" {

			detailSV.ChangeStatus = append(detailSV.ChangeStatus, global.StatusDetail{
				Status: "Off",
				Time:   time.Now(),
			},
			)
			info := &global.ListStatus{
				ChangeStatus: detailSV.ChangeStatus,
			}
			var inInterface map[string]interface{}
			inter, _ := json.Marshal(info)
			json.Unmarshal(inter, &inInterface)
			var buf bytes.Buffer
			doc := map[string]interface{}{
				"query": map[string]interface{}{
					"match": map[string]interface{}{
						"_id": req.GetIdServer(),
					},
				},
				"script": map[string]interface{}{
					"source": "ctx._source.changeStatus=params.changeStatus;",
					"params": inInterface,
				},
			}
			if err := json.NewEncoder(&buf).Encode(doc); err != nil {
				log.Fatalf("Error update: %s", err)
			}
			res, err := global.DBels.UpdateByQuery(
				[]string{"server-elastest"},
				global.DBels.UpdateByQuery.WithBody(&buf),
				global.DBels.UpdateByQuery.WithContext(context.Background()),
				global.DBels.UpdateByQuery.WithPretty(),
			)
			if err != nil {
				log.Fatalf("Error update: %s", err)
			}
			defer res.Body.Close()
		}

	}
	filter := bson.M{"_id": id}
	update := bson.M{"$set": bson.M{
		"password":   req.GetPassword(),
		"updated_at": time.Now(),
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, er := global.DB.Collection("servertest").UpdateOne(ctx, filter, update)
	if er != nil {
		log.Fatal(err)
	}
	resp := &serverpb.MessResponse{
		Mess: "Done",
	}
	RemoveCache("indexCache")
	RemoveCache("statusCache")

	return resp, nil
}
func SendMail(mail string) {
	email := mail
	from := "thaithteam47@gmail.com"
	password := "anhemtui123"
	to := []string{email}
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	auth := smtp.PlainAuth("", from, password, smtpHost)
	for {
		collection := global.DB.Collection("servertest")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cur, err := collection.Find(ctx, bson.M{})
		result := ""
		if err != nil {
			log.Fatal(err)
		}
		if cur != nil {
			for cur.Next(context.TODO()) {
				var elem global.InfoServer
				er := cur.Decode(&elem)
				if er != nil {
					log.Fatal(err)
				}
				var r map[string]interface{}
				var buf bytes.Buffer
				query := map[string]interface{}{
					"query": map[string]interface{}{
						"match": map[string]interface{}{
							"_id": elem.ID.Hex(),
						},
					},
				}
				if err := json.NewEncoder(&buf).Encode(query); err != nil {
					log.Fatalf("Error encoding query: %s", err)
				}
				res, err := global.DBels.Search(
					global.DBels.Search.WithContext(context.Background()),
					global.DBels.Search.WithIndex("server-elastest"),
					global.DBels.Search.WithBody(&buf),
					global.DBels.Search.WithTrackTotalHits(true),
					global.DBels.Search.WithPretty(),
				)
				if err != nil {
					log.Fatalf("Error getting response: %s", err)
				}
				defer res.Body.Close()
				if !res.IsError() {
					if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
						log.Fatalf("Error parsing the response body: %s", err)
					}
					var detailSV global.ListStatus
					for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {
						m, _ := json.Marshal(hit.(map[string]interface{})["_source"])
						err := json.Unmarshal(m, &detailSV)
						if err != nil {
							log.Fatalf("Error getting response: %s", err)
						}
					}
					if len(detailSV.ChangeStatus) > 0 {
						result += "Id: " + elem.ID.Hex() + ", Server name: " + elem.ServerName + ", Status: " + detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status + "\n"
					}
				}
			}
		}
		msg := []byte("To:" + email + "\r\n" +
			"Subject: Daily monitoring report of server status\r\n" +
			"\r\n" +
			result + "\r\n")

		err = smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, msg)
		if err != nil {
			log.Fatalf("Error getting response: %s", err)
		}
		time.Sleep(24 * time.Hour)
	}
}

var (
	grpcServerEndpoint = flag.String("grpc-server-endpoint", ":9090", "gRPC server endpoint")
)

func preflightHandler(w http.ResponseWriter, r *http.Request) {
	headers := []string{"Content-Type", "Accept", "Authorization"}
	w.Header().Set("Access-Control-Allow-Headers", strings.Join(headers, ","))
	methods := []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
	w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ","))
	glog.Infof("preflight request for %s", r.URL.Path)
	return
}
func allowCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			if r.Method == "OPTIONS" && r.Header.Get("Access-Control-Request-Method") != "" {
				preflightHandler(w, r)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func run(lis net.Listener) error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	opts := []grpc.DialOption{grpc.WithInsecure()}
	gwmux := runtime.NewServeMux()
	err := gw.RegisterServerServiceHandlerFromEndpoint(ctx, gwmux, *grpcServerEndpoint, opts)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/", gwmux)
	mux.HandleFunc("/swagger/", serveSwaggerFile)
	serveSwaggerUI(mux)
	s := &http.Server{Handler: allowCORS(mux)}
	return s.Serve(lis)
}

func serveSwaggerFile(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "swagger.json") {
		fmt.Printf("Not Found: %s\r\n", r.URL.Path)
		http.NotFound(w, r)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/swagger/")
	p = path.Join("../protos", p)
	fmt.Printf("Serving swagger-file: %s\r\n", p)
	http.ServeFile(w, r, p)

}
func serveSwaggerUI(mux *http.ServeMux) {
	fs := http.FileServer(http.Dir("./swaggerui"))
	prefix := "/swaggerui/"
	mux.Handle(prefix, http.StripPrefix(prefix, fs))
}
func clientGolang(lis net.Listener) error {
	flag.Parse()
	defer glog.Flush()
	return run(lis)
}
func serverGolang(lis net.Listener) error {
	s := grpc.NewServer()
	serverpb.RegisterServerServiceServer(s, &server{})
	err := s.Serve(lis)
	return err
}
func main() {
	fmt.Println("running")
	for {
		lis, err := net.Listen("tcp", ":9090")
		if err != nil {
			log.Fatalf("err while create listen %v", err)
		}
		m := cmux.New(lis)
		grpcListener := m.MatchWithWriters(cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"))
		httpListener := m.Match(cmux.HTTP1Fast())
		g := new(errgroup.Group)
		g.Go(func() error { return serverGolang(grpcListener) })
		g.Go(func() error { return clientGolang(httpListener) })
		//go SendMail("thteam47@gmail.com")
		go UpdateStatus()
		g.Go(func() error { return m.Serve() })
		log.Println("run server:", g.Wait())
	}
}
