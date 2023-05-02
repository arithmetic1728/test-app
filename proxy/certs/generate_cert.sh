rm *.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 >& ca_private_key.pem
openssl req -x509 -key ca_private_key.pem -subj /CN=proxy >& ca_cert.pem