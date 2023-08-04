# proto 파일을 읽고 pb.go와 _grpc.pb.go를 생성해줌

protoc --go_out=. --go_opt=paths=source_relative  \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative  \
proxyGrpc.proto
