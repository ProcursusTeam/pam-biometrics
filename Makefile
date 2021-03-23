compile:
	$(CC) $(CFLAGS) -c util.c -o util.o
	$(CC) $(CFLAGS) -lpam -framework Foundation -framework LocalAuthentication -shared util.o pam-biometrics.m -o pam-biometrics.so
