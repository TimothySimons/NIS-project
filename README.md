# Network and Internet Security Practical
The premise of the Client application is to enable Bob to send a secret message to Alice. In the example execution of the application, Bob will be making the request and Alice will be listening for the request from Bob. The key stores for each of the clients are found in the resources folder. The secret message to be sent to Alice is in the bob sub-folder under resources.

## Getting Started
If you wish to create your own java key stores, you will have to follow the tutorials outlined in [Oracle's Documentation] (https://docs.oracle.com)
Sample java key stores have been included for your convenience.

### Prerequisites
 To run the application, you will need:
 * a java key store for the listening client
 * a java key store for the connecting client
 * each key store needs to contain the client's signed certificate, their private key and the certificate of a trusted Certification Authority.
 * a secret .txt message to be sent from the connecting client to the listening client
 Sample java key stores have been provided for testing.

 ## Application Execution
You can run the sample client and the sample server programs on different machines connected to the same network, or you can run them both on one machine but from different terminal windows.

java ClientMain ../resources/alice/alicekeystore.jks alice alice123 thecaroot 1234
java ClientMain ../resources/bob/bobkeystore.jks bob bob123 thecaroot LAPTOP-9M1CDRT7 1234 ../resources/bob/secret_msg.txt
