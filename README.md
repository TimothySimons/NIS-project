# Network and Internet Security Practical
The premise of the Client application is to enable Bob to send a secret message to Alice. In the example execution of the application, Bob will be making the request and Alice will be listening for the request from Bob. The security features in this application are similar to that of PGP.

## Getting Started
If you wish to create your own java key stores, you will have to follow the tutorials outlined in Oracle's documentation https://docs.oracle.com

### Prerequisites
 To run the application, you will need:
 * a java key store for the listening client
 * a java key store for the connecting client
 * each key store needs to contain the client's signed certificate, their private key and the certificate of a trusted Certification Authority.
 * a secret .txt message to be sent from the connecting client to the listening client

 Sample java key stores and a secret message have been provided for testing.

## Running the application
A Makefile is added for convenient compilation. If you do not have the make utility, you can simply compile and run the program from src.

### Compilation
To compile the Client application
```
make
```

To remove class files from bin
```
make clean
```

### Execution
Navigate to the bin directory and execute two instances of the Client application on two separate terminals with the relevant command-line arguments. Most of these arguments relate to the respective client's java key stores. The only argument that requires modification is the `<host name>` argument which should be changed to the name of your machine. Execute the listening client instance on one terminal and then execute the connecting client instance on another terminal.
```
java ClientMain ../resources/alice/alicekeystore.jks alice alice123 thecaroot 1234
java ClientMain ../resources/bob/bobkeystore.jks bob bob123 thecaroot LAPTOP-ABC 1234 ../resources/bob/secret_msg.txt
```

More generally, the application is executed as follows
```
java ClientMain <JKS-filepath> <alias> <password> <ca-root-alias> <port-number>
java ClientMain <JKS-filepath> <alias> <password> <ca-root-alias> <host name> <port number> <secret-msg-filepath>
```

To find out your machine's ```<host name>```, simply execute the following in the terminal
```
hostname
```
