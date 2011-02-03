all: lcrypto

lcrypto:
	./build

test:
	./build test

clean:
	rm -rf java/crypto/build/
	rm -rf out/
