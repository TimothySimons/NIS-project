You can run the sample client and the sample server programs on different machines connected to the same network, or you can run them both on one machine but from different terminal windows.

java ClientMain ../resources/alice/alicekeystore.jks alice alice123 thecaroot 1234
java ClientMain ../resources/bob/bobkeystore.jks bob bob123 thecaroot LAPTOP-9M1CDRT7 1234 ../resources/bob/secret_msg.txt
