1. Download you certificate from VIP Admin Console
2. Extract the private key - unencrypted
	> openssl pkcs12 -in vip.p12 -nocerts -nodes -out vip-key.pem
3. Extract the public certificate
	> openssl pkcs12 -in *.p12 -clcerts -nokeys -out vip-cert.crt