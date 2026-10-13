# syntax=docker/dockerfile:1
FROM golang:1.26.9-alpine AS build
WORKDIR /src
ENV GOWORK=off CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY tests ./tests
RUN go test -c -trimpath -o /out/owner-mail.test ./tests/owner_mail
RUN go test -c -trimpath -o /out/enrollment.test ./tests/integration

FROM scratch AS runtime
WORKDIR /module/tests/owner_mail
COPY --from=build --chown=65532:65532 /out/owner-mail.test /owner-mail.test
COPY --from=build --chown=65532:65532 /out/enrollment.test /enrollment.test
COPY --chown=65532:65532 tests/testdata /module/tests/testdata
USER 65532:65532
ENTRYPOINT ["/owner-mail.test"]
CMD ["-test.run=TestA4RealSMTPUsesDurableOwnerCorrelation", "-test.timeout=30s"]
