CFLAGS ?= -arch arm64 -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path)

all:
	$(CC) $(CFLAGS) -c util.c -o util.o
	$(CC) $(CFLAGS) -fobjc-arc -bundle util.o pam_biometrics.m -o pam_biometrics.so $(LDFLAGS) -lpam -framework CoreFoundation -framework LocalAuthentication

clean:
	rm -f *.o *.so

.PHONY: all