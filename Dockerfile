FROM golang:1.15-buster as build
WORKDIR /go/src/app
ADD . /go/src/app

RUN go get -d -v ./...
RUN go build -o /go/bin/app github.com/cheahjs/hyperoptic_zte_exporter/cmd/hyperoptic_zte_exporter

FROM discolix/base:debug
COPY --from=build /go/bin/app /
ENTRYPOINT ["/app"]
