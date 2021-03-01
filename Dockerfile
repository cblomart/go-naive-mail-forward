FROM cblomart/gobasebuild:latest AS builder

ENV GO111MODULE=on \
    CGO_ENABLED=1

# install necessary tools
RUN apt-get update &&\
    apt-get install -y --no-install-recommends tzdata zip ca-certificates &&\
    apt-get clean &&\
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# compress tzinfo
WORKDIR /usr/share/zoneinfo
RUN zip -q -r -0 /zoneinfo.zip .

WORKDIR /build

# cache modules that shouldn't change often
COPY go.sum .
COPY go.mod .
RUN go mod download

# copy sources
COPY . .

# code checks
RUN staticcheck  ./...
RUN	gofmt -s -d .
RUN	go vet ./...
RUN	gosec --quiet ./...
RUN revive .
RUN gocyclo -over 10 .
#RUN varcheck
#RUN structcheck
#RUN aligncheck

# build the app
RUN go generate ./... \
    && go build -ldflags '-d -s -w' -a -tags netgo -installsuffix netgo . \
    && upx -qq --best --lzma ./go-naive-mail-forward

# prepare the distribution folder
WORKDIR /dist
RUN cp /build/go-naive-mail-forward ./go-naive-mail-forward

# create a folder from where to run
RUN mkdir /data

# create the minimal image
FROM scratch

# set zoneinfo
ENV ZONEINFO /zoneinfo.zip
COPY --from=builder /zoneinfo.zip /

# set ca-certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# copy dist folder
COPY --chown=0:0 --from=builder /dist /
COPY --chown=0:0 --from=builder /data /data
#USER 65534
WORKDIR /data

# start the smtp server
ENTRYPOINT ["/go-naive-mail-forward"]

# set a healtcheck
HEALTHCHECK --start-period=5s CMD [ "/go-naive-mail-forward","-check"]