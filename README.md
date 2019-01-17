# Internet Security and Privacy - IK2206

1. Compile the files:
```
javac *.java
```
2. Open 2 new command prompt windows and navigate to the path where the files are located. For example: 
```
cd "C:\Users\charalav\Documents\VPN"
```

In the first one run the ForwardServer file:
```
java ForwardServer --handshakeport=2206 --usercert=server.pem --cacert=ca.pem --key=server-private.der
```

In the second one run the ForwardClient file:
```
java ForwardClient --handshakehost=127.0.0.1 --handshakeport=2206 --targethost=127.0.0.1 --targetport=6789 --usercert=client.pem --cacert=ca.pem --key=client-private.der
```

3. Open 2 new command prompt windows to actually send messages. 

Supposing that netcat is correctly configured and installed, in the first command prompt start an nc server that listens for incoming TCP connections on port 6789 by typing: 
```
nc -l -p 6789
```

And in the second one, to connect to the server , type e.g:
```
nc 192.168.1.105 xxxx
```

4. Messages are successfully forwarded from server to client and vice versa.
