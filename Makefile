TARGET := main
ATTACH := attach
TARGET_BPF := $(TARGET).bpf.o

BPF_SRC := bpf/*.bpf.c
LIBBPF_HEADERS := /usr/include/bpf

.PHONY: all
all: $(TARGET) $(TARGET_BPF) $(ATTACH)

$(TARGET): main.go
	go build -o $(TARGET)

$(ATTACH): cmd/attach/main.go
	go build -o $(ATTACH) ./cmd/attach

$(TARGET_BPF): $(BPF_SRC)
	clang -I $(LIBBPF_HEADERS) -I /usr/include/x86_64-linux-gnu -I ./bpf -I ./bpf/headers \
	-O2 -g -c -target bpf \
	-o $@ $<

.PHONY: clean
clean:
	rm -f $(TARGET) $(ATTACH) $(TARGET_BPF)