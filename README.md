# Yak : Ycash/Zcash Payment Detector

![Go on, call me Fluffy one more time!](https://github.com/ChileBob/Yak/blob/main/images/yak-600x473.png?raw=true)

- Connects to a Zcash or Ycash node via ZMQ, listens for transactions & new blocks.
- Decrypts shielded outputs with a client viewkey, then broadcasts AES256 encrypted notifications.
- Broadcasts unencrypted transparent transactions and mined txids.
- Viewkeys for monitoring shielded transactions are exchanged by encrypted memo.

This is a proof of concept and possibly a BAD IDEA - USE WITH CAUTION.

# Current Status

Important, please note :- 
- ZMQ HAS SECURITY IMPLICATIONS - MAKE SURE YOU UNDERSTAND THEM !!!
- Any device can connect to the websocket server.
- All devices receive all broadcasts, even encrypted stuff they cant read.
- Nodes & tickers need encryption keys to post broadcasts.

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
- Decrypts AES256 shielded notifications sent by yak-yec & yak-zec
- Triggers website URI to enable payment processing

yak-yec :-
- Ycash fullnode (ycashd) connector & websocket client.
- Run it from a terminal AS THE SAME USER that runs ycashd
- Streams transparent transaction outputs.
- Streams confirmed (mined) transactions
- Decode shielded outputs using viewkeys.
  - AES256 encrypts and broadcasts shielded notifications.
- Basic fee mechanism (per block) for monitoring a viewkey.
- Viewkey registration is by encrypted memo.

yak-zec :-
- Will do everything yak-yec does but does it for Zcash
- Long way behind yak-yec & needs updating...(sorry)

yak-coingeko
- Broadcasts price updates once a minute.
- Prices are for Zcash & Ycash
- Currencies are USD, EUR, GBP
- See https://coingecko.com/api for more details.

