FROM cblomart/gobasebuild:latest AS builder

ENV GO111MODULE=on \
    CGO_ENABLED=1

WORKDIR /build

# cache modules that shouldn't change often
COPY go.sum .
COPY go.mod .
RUN go mod download

# copy sources
COPY . .

# code checks
RUN staticcheck -f stylish  ./... \
	&& gofmt -s -d . \
	&& go vet ./... \
	&& golint ./... \
	&& gosec ./...

# build the app
RUN go generate ./... \
    && go build -ldflags '-d -s -w' -a -tags netgo -installsuffix netgo . \
    && upx -qq --best --lzma ./go-naive-mail-forward

# prepare the distribution folder
WORKDIR /dist
RUN cp /build/go-naive-mail-forward ./go-naive-mail-forward

# copy necessary distributed libraries
#RUN ldd go-naive-mail-forward | tr -s '[:blank:]' '\n' | grep "^/" | xargs -I % sh -c 'mkdir -p $(dirname ./%); cp % ./%'
#RUN mkdir -p lib64 && cp /lib64/ld-linux-x86-64.so.2 lib64/

# create a folder from where to run
RUN mkdir /data

# create the minimal image
FROM scratch

# copy dist folder
COPY --chown=0:0 --from=builder /dist /
COPY --chown=0:0 --from=builder /data /data
#USER 65534
WORKDIR /data

# start the smtp server
ENTRYPOINT ["/go-naive-mail-forward"]

# set a healtcheck
HEALTHCHECK --start-period=5s CMD [ "/go-naive-mail-forward","-check"]