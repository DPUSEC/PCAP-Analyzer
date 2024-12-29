FROM golang:1.23.3

WORKDIR /build
COPY . /build

RUN apt update -y && apt install -y tshark libpcap-dev
RUN go mod tidy
RUN go build -o app-server

WORKDIR /app
RUN mv /build/app-server /app/app-server
RUN rm -rf /build

CMD ["/app/app-server"]
