gcc -c sha2.c hmac_sha2.c uECC.c
gcc -c attacker_client.c attacker_server.c server_lib.c
gcc -o attacker_server attacker_server.o sha2.o hmac_sha2.o uECC.o
gcc -o attacker_client attacker_client.o server_lib.o sha2.o hmac_sha2.o uECC.o
rm *.o
