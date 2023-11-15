all: server.c client.c
	gcc -o server server.c -lpthread -lcrypto -lssl
	gcc -o client client.c -lpthread -lcrypto -lssl

clean: 
	rm -rf server client