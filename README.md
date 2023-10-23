# Decapsulate HP-ERM RSPAN Protocol with XDP


Run:

```
dnf config-manager --set-enabled powertools
# or
dnf config-manager --set-enabled crb
```
```
dnf install clang llvm gcc libbpf libbpf-devel libxdp libxdp-devel xdp-tools bpftool kernel-headers
```

Compile XDP program
Note: Because we have CO.RE we compile it to one system and we can run it everywhere.
```
clang -O2 -target bpf -c xdp.c -o xdp.o
```
Install XDP program
```
ip link set dev enp0s3 xdp obj xdp.o sec .text
```

Remove XDP program
```
ip link set dev enp0s3 xdp off
```

