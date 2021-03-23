compile:
	$(CC) $(CFLAGS) -lpam -framework Foundation -framework LocalAuthentication -shared pam-biometric.m -o pam-biometric.so
