# Yak : Ycash/Zcash Payment Detector

![Go on, call me Fluffy one more time!](https://github.com/ChileBob/Yak/blob/main/images/yak-600x473.png?raw=true)

- Ycash/Zcash clients connect to their full nodes via ZMQ & listen for raw transactions.
- Decrypted shielded outputs are broadcast as AES256 ciphertext.
- Transactions are confirmed when they're mined.
- To monitor a viewkey, send it by encrypted memo.

This is a proof of concept and possibly a REALLY BAD IDEA - use with caution.

# Current Status

Important, please note :- 
- No authentication.
- ZMQ HAS SECURITY IMPLICATIONS - MAKE SURE YOU UNDERSTAND THEM !!!
- Any device can connect to the websocket server and receive BINARY, BASE64 or HEX data.

To enable ZMQ on your ZCASH node, add this to zcash.conf :-  
- zmqpubrawtx=tcp://127.0.0.1:28232
- zmqpubhashblock=tcp://127.0.0.1:28232

To enable ZMQ on your YCASH node, add this to ycash.conf :-  
- zmqpubrawtx=tcp://127.0.0.1:28832
- zmqpubhashblock=tcp://127.0.0.1:28832

yak-yak :-
- Websocket server, run it from a terminal.
- Broadcasts everything it receives from yec-yak & zec-yak to all connected clients.
- Supports binary & base64 transport.
- Simple authentication, rate limits unauthenticated clients.

yak-client :-
- Websocket client, run it from a terminal.
- Listens to broadcasts from yak-yak.
- Decrypts AES256 shielded notifications sent by yak-zec
- Debugging tool for displaying broadcasts.

yak-web :-
- Websocket client, run it from a terminal.
- Connects a website to yak-yak.
- Decrypts shielded broadcasts using a viewkey & triggers a URI 

yak-zec :-
- Zcash fullnode (zcashd) connector/client.
- Run it from a terminal AS THE SAME USER that runs zcashd
- Streams transparent transaction outputs.
- Streams confirmed (mined) transactions
- Decode shielded outputs using viewkeys.
  - AES256 encrypts and broadcasts shielded notifications.
- Basic fee mechanism (per block) for monitoring a viewkey.
- Viewkey registration is by encrypted memo.

yak-yec :-
- Waiting on the ycash version of librustzcash
- Will do everything yak-zec does but for Ycash
- (Incidentally, the idea originally came from the Ycash people)

Known issues :-
- The clients do not attempt reconnection if the server is restarted.
