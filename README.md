# Yak : Ycash/Zcash Payment Detector

![Go on, call me Fluffy one more time!](https://github.com/ChileBob/Yak/blob/main/images/yak-600x473.png?raw=true)

- Connects to a Zcash or Ycash node via ZMQ & listens for transactions & blocks.
- Decrypted shielded outputs with a viewkey, then broadcasts as AES256 ciphertext via a websocket server.
- Broadcasts transparent transactions and mined txids.
- Shielded viewkeys for monitoring are received by encrypted memo.

This is a proof of concept and possibly a REALLY BAD IDEA - use with caution.

# Current Status

Important, please note :- 
- No authentication.
- ZMQ HAS SECURITY IMPLICATIONS - MAKE SURE YOU UNDERSTAND THEM !!!
- Any device can connect to the websocket server.

To enable ZMQ on your ZCASH node, add this to zcash.conf :-  
- zmqpubrawtx=tcp://127.0.0.1:28232
- zmqpubhashblock=tcp://127.0.0.1:28232

To enable ZMQ on your YCASH node, add this to ycash.conf :-  
- zmqpubrawtx=tcp://127.0.0.1:28832
- zmqpubhashblock=tcp://127.0.0.1:28832

# Components :- 

yak-yak :-
- Websocket server, run it from a terminal.
- Broadcasts everything it receives from yec-yak & zec-yak to all connected clients.
- Supports binary & base64 transport.
- Simple authentication, rate limits un-authenticated clients.

yak-cli :-
- Websocket command line client, run it from a terminal.
- Listens to broadcasts from yak-yak & displays.
- Decrypts AES256 shielded notifications sent by yak-zec
- Triggers website URI to enable payment processing

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
- Does everything yak-zec does but does it for Ycash
- (Incidentally, the idea for this code came from the Ycash people)

Known issues :-
- The clients do not attempt reconnection if the server is restarted.
