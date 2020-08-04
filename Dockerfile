# Start by building the application.
FROM golang:1.14-buster as build

WORKDIR /go/src/app
ADD . /go/src/app

RUN go get -d -v ./...
RUN go build -o /go/bin/app github.com/cheahjs/hyperoptic_tilgin_exporter/cmd/hyperoptic_tilgin_exporter

# Now copy it into our base image.
FROM gcr.io/distroless/base-debian10
COPY --from=build /go/bin/app /
ENTRYPOINT ["/app"]
