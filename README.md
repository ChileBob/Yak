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

yak-web :-
- Websocket server, run it from a terminal.
- It broadcasts everything it receives from yec-yak & zec-yak to all connected clients.

yak-client :-
- Websocket client, run it from a terminal.
- Listens to broadcasts from yak-web.
- Decrypts AES256 shielded notifications sent by yak-zec

yak-zec :-
- Zcash fullnode (zcashd) connector/client.
- Run it from a terminal AS THE SAME USER that runs zcashd
- Make sure the node client (zcash-cli) is in the $PATH.
- Streams transparent transaction outputs.
- Streams confirmed (mined) transactions
- Attempts to decode shielded outputs using viewkeys.
  - If successful, AES256 encrypts and sends details for broadcast.
  - Viewkeys are sent by encrypted memo.
  - Broadcasts are encrypted with a hash of the viewkey.
- Basic fee mechanism (per block) for monitoring a viewkey.

yak-yec :-
- Waiting on the ycash version of librustzcash
- Will do everything yak-zec does but for Ycash
- (Incidentally, the idea originally came from the Ycash people)

yak-yak :-
- Not yet written, messaging client

Known issues :-
- The clients do not attempt reconnection if the server is restarted.
