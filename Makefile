compile:
	$(CC) $(CFLAGS) -c util.c -o util.o
	$(CC) $(CFLAGS) -lpam -framework Foundation -framework LocalAuthentication -shared util.o pam-biometric.m -o pam-biometric.so
