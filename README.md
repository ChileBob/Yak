# Yak : Ycash/Zcash payment detector &amp; messaging.

![Go on, call me Fluffy one more time!](https://github.com/ChileBob/Yak/blob/main/images/yak-600x473.png?raw=true)

The client listens to ZMQ for raw transactions & broadcasts via a websocket echo server, it listens for new blocks & broadcasts confirmations for mined transactions.

Any device can connect to the websocket server and receive BINARY, BASE64 or HEX data.

This is a proof of concept and probably a REALLY BAD IDEA - use with caution.

# Current Status

Important, please note :- 
- No authentication.
- No encryption.
- ZMQ HAS SECURITY IMPLICATIONS - MAKE SURE YOU UNDERSTAND THEM !!!

To enable ZMQ on your ZCASH node, add this to zcash.conf :-  
- zmqpubrawtx=tcp://127.0.0.1:28232
- zmqpubhashblock=tcp://127.0.0.1:28232

To enable ZMQ on your YCASH node, add this to ycash.conf :-  
- zmqpubrawtx=tcp://127.0.0.1:28832
- zmqpubhashblock=tcp://127.0.0.1:28832

yak-web :-
- This is the websocket server, run it from a terminal.
- It broadcasts everything it receives from yec-yak & zec-yak to all connected clients.

yec-yak :-
- Run this on your fullnode AS THE SAME USER that runs ycashd, run it from a terminal.
- Make sure the node client (zcash-cli/ycash-cli) is in the $PATH.
- It listens to rawtransactions & new blocks from ZMQ, decodes those it can with viewkeys & sends updates to ystream-server.

zec-yak :-
- The Zcash version of yec-yak.

yak-yak :-
- Not yet written, this is a command line websocket client for debugging & testing.

Known issues :-
- The client does not attempt reconnection if the server is restarted.
