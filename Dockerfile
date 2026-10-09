FROM gcr.io/distroless/static-debian13:nonroot
ARG TARGETARCH
ARG VERSION=0.1.0
COPY --chmod=0555 dist/fencepost-${VERSION}-linux-${TARGETARCH} /fencepost
WORKDIR /data
ENTRYPOINT ["/fencepost"]
CMD ["--help"]
