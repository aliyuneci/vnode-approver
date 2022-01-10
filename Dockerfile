FROM golang:1.16 as builder

ENV PATH /go/bin:/usr/local/go/bin:$PATH
ENV GOPATH /go
ENV GOPROXY https://mirrors.aliyun.com/goproxy/

COPY . /go/src/github.com/aliyuneci/vnode-approver

WORKDIR /go/src/github.com/aliyuneci/vnode-approver

RUN make build
RUN cp ./bin/vnode-approver /usr/bin/vnode-approver

FROM alpine:3.15

COPY --from=builder /usr/bin/vnode-approver /usr/bin/vnode-approver