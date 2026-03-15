CC = clang
CFLAGS = -fobjc-arc -Wall -Wextra -Wno-unused-parameter -framework Foundation
DEPLOYMENT_TARGET = -mmacosx-version-min=12.0

SRCS = optool/main.m optool/operations.m optool/headers.m optool/NSData+Reading.m
TARGET = build/optool
BUILDDIR = build

# Build universal binary by default
ARCHS = -arch arm64 -arch x86_64

.PHONY: all clean install

all: $(TARGET)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(TARGET): $(SRCS) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(DEPLOYMENT_TARGET) $(ARCHS) -o $@ $(SRCS)

debug: $(SRCS) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(DEPLOYMENT_TARGET) $(ARCHS) -g -DDEBUG -o $(TARGET) $(SRCS)

clean:
	rm -rf $(BUILDDIR)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/optool
