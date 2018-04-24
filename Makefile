generate:
	openssl req -x509 -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem -subj "/C=US/ST=Montana/L=Hope County/O=Seed Family/OU=Project Eden Gate/CN=peg.org"

clean:
	rm -f *.pem *.pyc