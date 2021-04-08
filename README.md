# Yak : Ycash/Zcash Payment Detector

![Go on, call me Fluffy one more time!](https://github.com/ChileBob/Yak/blob/main/images/yak-600x473.png?raw=true)

- Ycash/Zcash clients connect to their full nodes via ZMQ & listen for raw transactions.
- Decrypted shielded outputs are broadcast as AES256 ciphertext.
- Transactions are confirmed when they are mined in a new block.
- Adding a viewkey is done by sending an encrypted memo.

This is a proof of concept and possibly a REALLY BAD IDEA - use with caution.

# Current Status

Important, please note :- 
- No authentication.
- No encryption.
- ZMQ HAS SECURITY IMPLICATIONS - MAKE SURE YOU UNDERSTAND THEM !!!
- Any device can connect to the websocket server and receive BINARY, BASE64 or HEX data.

To enable ZMQ on your ZCASH node, add this to zcash.conf :-  
- zmqpubrawtx=tcp://127.0.0.1:28232
- zmqpubhashblock=tcp://127.0.0.1:28232

To enable ZMQ on your YCASH node, add this to ycash.conf :-  
- zmqpubrawtx=tcp://127.0.0.1:28832
- zmqpubhashblock=tcp://127.0.0.1:28832

yak-web :-
- This is the websocket server, run it from a terminal.
- It broadcasts everything it receives from yec-yak & zec-yak to all connected clients.

zec-yak :-
- Zcash fullnode (zcashd) connector/client.
- Run it from a terminal AS THE SAME USER that runs zcashd.
- Make sure the node client (zcash-cli) is in the $PATH.
- Decrypted transactions are encrypted using the viewkey and broadcast via yak-web.

yec-yak :-
- Waiting on the ycash version of librustzcash

yak-yak :-
- Not yet written, its a command line client for debugging & testing.

Known issues :-
- The clients do not attempt reconnection if the server is restarted.
