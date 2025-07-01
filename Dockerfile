FROM rockylinux:9-minimal

RUN sed -i 's/enabled=0/enabled=1/' /etc/yum.repos.d/rocky-devel.repo && \
    microdnf install -y --nobest go clang llvm libbpf libbpf-devel glibc-devel glibc-devel.i686

COPY src /src
WORKDIR /src

RUN  go generate && go build -o /build/hopper

CMD [ "bash" ]