all: lcrypto gss

lcrypto:
	./build

# depends on lcrypto
gss:
	./build gss

# depends on lcrypto
test:
	./build test

clean:
	rm -rf java/crypto/build/
	rm -rf out/
