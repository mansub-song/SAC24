module grpcClient

go 1.20

require (
	github.com/SherLzp/goRecrypt v0.0.0-20200405110533-a55273ae0aeb
	github.com/mansub-song/proxyGrpc v0.0.0
	google.golang.org/grpc v1.57.0
)

require (
	github.com/fentec-project/bn256 v0.0.0-20190726093940-0d0fc8bfeed0 // indirect
	github.com/fentec-project/gofe v0.0.0-20220829150550-ccc7482d20ef // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.11.0 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sys v0.10.0 // indirect
	golang.org/x/text v0.11.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230525234030-28d5490b6b19 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
)

replace (
	github.com/SherLzp/goRecrypt => ../goRecrypt
	github.com/mansub-song/proxyGrpc => ../proxyGrpc
)
