# protoc --go_out=. --go_opt=paths=source_relative \
#     --go-grpc_out=. --go-grpc_opt=paths=source_relative \
#     Message.proto

# run the following code at DyCAPS/
protoc --proto_path=pkg/protobuf/ --go_out=pkg/  Message.proto 