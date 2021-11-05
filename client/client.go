package main

import (
	"context"
	"flag"
	"fmt"

	//"io"
	"path"
	"strings"

	// "io"
	// "strings"

	//"fmt"

	//"log"
	"net/http"

	gw "example.com/m/serverpb"
	swagger "example.com/m/swagger"
	assetfs "github.com/elazarl/go-bindata-assetfs"
	"github.com/golang/glog"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"google.golang.org/grpc"
)

var (
	// command-line options:
	// gRPC server endpoint
	grpcServerEndpoint = flag.String("grpc-server-endpoint", "localhost:9090", "gRPC server endpoint")
)

func run() error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Register gRPC server endpoint
	// Note: Make sure the gRPC server is running properly and accessible
	// gwmux := http.NewServeMux()
	// gwmux.HandleFunc("/swagger.json", func(w http.ResponseWriter, req *http.Request) {
	// 	io.Copy(w, strings.NewReader(gw.Swagger))
	// })
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
	return http.ListenAndServe(":9090", mux)
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
	fileServer := http.FileServer(&assetfs.AssetFS{
		Asset:    swagger.Asset,
		AssetDir: swagger.AssetDir,
		Prefix:   "swaggerui",
	})
	prefix := "/swaggerui/"
	mux.Handle(prefix, http.StripPrefix(prefix, fileServer))
}
func main() {
	// var conn *grpc.ClientConn
	// conn, err := grpc.Dial(":9090", grpc.WithInsecure())
	// if err != nil {
	// 	log.Fatalf("could not connect: %s", err)
	// }
	// defer conn.Close()
	// c := serverpb.NewServerServiceClient(conn)
	// sv := serverpb.ExportRequest{
	// 	Page: false,
	// }
	// resp, err := c.Export(context.Background(), &sv)
	// if err != nil {
	// 	log.Fatalf("Error when calling: %s", err)
	// }
	// fmt.Println(resp.GetUrl())

	flag.Parse()
	defer glog.Flush()

	if err := run(); err != nil {
		glog.Fatal(err)
	}
}
