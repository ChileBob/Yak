#!/usr/bin/perl
#
# yak : stratum mining
#
# MIT License (ChileBob)
#
# Zcash : zs1a7qnkg8hr74ujj08jhjcdfs7s62yathqlyn5vd2e8ww96ln28m3t2jkxun5fp7hxjntcg8ccuvs
# Ycash : ys17fsj64ydl93net807xr00ujz2lnrf22cjf4430vvz69vpaat8t3hrdjmkvj7thrw4fdaz7l0pns

package stratum;

my $debug = 0;																# debug verbosity for this package

our $pool_listen;
our $pool_select;
our $pool_target = '007ffff000000000000000000000000000000000000000000000000000000000';

our $MINER_DISCONNECT  = 0x00;		# - disconnected

our $MINER_NEW         = 0x01;		# - new connection
our $MINER_SUBSCRIBED  = 0x02;		# - subscribed

our $MINER_AUTHORIZED  = 0x03;		# - authenticated
our $MINER_IDLE        = 0x10;		# - idle
our $MINER_TARGETED    = 0x11;		# - targetted
our $MINER_ACTIVE      = 0x12;		# - active (mining)


my $MINER_TCP = 0x01;			# direct connection
my $MINER_WEB = 0x02;			# via websocket

#########################################################################################################################################################################
#
# CHANGING ANYTHING BELOW THIS LINE IS A REALLY BAD IDEA !! 
#
#########################################################################################################################################################################

use Data::Dumper;														# debugging

use IO::Handle;															# socket handlers for mining
use IO::Socket;
use IO::Select;

my $devfee_address  = 'smN4pgFNjLmCMrawa9nqqb7MxYsg9w48Ln1';									# testnet devfee address
# my $devfee_address  = 's1YqPfBU6Z9MhnWrPkYBNtUaCzhjno1kKSP';									# ChileBob spends this on wine, women & song

our $devfee_percent = 0.25;													# .....not much on song! :-)

my $poolfee_address = '';													# pool address, overwritted from main config & command line
my $poolfee_percent = 0.25;													# Default pool fee

my $miner;															# miner (config/state)
my $miner_conn;															# miner (connection hash)

my $miner_idx = 1;														# miner client counter

my $running = 0;														# runtime flag

my $timer_interval = 15;													# timer reset (seconds), refresh miner tasks

my $timer_timeout = 60;														# timeout (seconds), clients inactive for this long are disconnected

#######################################################################################################################################
#
# Start stratum server 
#
sub start {

	my ($port, $address, $fee) = @_;											# listening port number & pool address

	if ($address && $port) {

		$poolfee_address = $address;											# pool params 
		$poolfee_percent = 0 + $fee;											
	
		$pool_listen = IO::Socket::INET->new (										# open listening socket
			LocalPort => $port,
			Proto => 'tcp',
			Listen => SOMAXCONN,											# limit is approx 32k sockets, so plenty
			reuse => 1,
			Blocking => 0												# non-blocking socket
		);
	
		$pool_select = IO::Select->new($pool_listen);								# port select handler
	
		$running = 1;													# set runtime flag
	}
	else {
		common::debug(0,"Failed to start stratum pool.");
		exit(1);
	}
}

#######################################################################################################################################
#
# Generate new work for all miners
#
sub new_work {

	my ($idx) = @_;		# miner id, specify if we're making work for ONE miner

	my @miner_id;
	if ($idx) {
		@miner_id = ( $idx ) ;
	}
	else {
		@miner_id = keys %$miner;
	}

	if ($running) {															# only if pool is ready to mine

		my $template = common::node_cli('getblocktemplate', '', '');

		foreach my $id (@miner_id) {

			if ($miner->{$id}->{'state'} >= $MINER_AUTHORIZED) {								# only for miners that are ready to work

				$miner->{$id}->{'work'}->{'tx_data'} = mining::make_coinbase($template, [ 				# coinbase transaction
					{ address => $miner->{$id}->{'address'}},
					{ address => $devfee_address, percent => $devfee_percent},
					{ address => $poolfee_address, percent => $poolfee_percent}
				]);
	
				my @tx_id = mining::hash_this($miner->{$id}->{'work'}->{'tx_data'});						# coinbase txid
	
				foreach my $tx ( @{$template->{'transactions'}} ) {							# add remaining transactions
					push @tx_id, $tx->{'hash'};
					$miner->{$id}->{'work'}->{'txdata'} .= $tx->{'data'};
				}
	
#				$miner->{$id}->{'work'}->{'target'} = $template->{'target'};						# mining difficulty target
				$miner->{$id}->{'work'}->{'target'} = $pool_target;
	
				$miner->{$id}->{'work'}->{'version'}    	  = unpack("H*", pack("L", $template->{'version'}));		# version    (little-endian)
				$miner->{$id}->{'work'}->{'merkleroot'} 	  = mining::merkleroot(\@tx_id);				# merkleroot (little-endian)
				$miner->{$id}->{'work'}->{'previousblockhash'} 	  = mining::reverse_bytes($template->{'previousblockhash'});	# previousblockhash (little-endian)
				$miner->{$id}->{'work'}->{'finalsaplingroothash'} = mining::reverse_bytes($template->{'finalsaplingroothash'});	# finalsaplingroothash (little-endian)
				$miner->{$id}->{'work'}->{'time'} 		  = unpack("H*", pack("L", time));				# epoch time (little-endian)
				$miner->{$id}->{'work'}->{'bits'} 		  = mining::reverse_bytes($template->{'bits'});			# block minimum difficulty (little-endian)
	
				$miner->{$id}->{'work'}->{'jobnumber'}++;									# increment job number
				$miner->{$id}->{'work'}->{'shares'} = 0;									# clear share counter
	
				if ( $miner->{$id}->{'state'} > $MINER_IDLE ) { 	# tag miner as idle
					$miner->{$id}->{'state'} = $MINER_IDLE;	
				}
			}
		}
	}
}

#######################################################################################################################################
#
# Check clients, read responses, send work, register shares, submit blocks
#
sub update {

	if ($running) {

		my @miner_ready = $pool_select->can_read(0); 								#TODO: MINING : Parse request from mining clients

		if (@miner_ready) {												# loop through all connections with requests
	
			foreach my $fh (@miner_ready) {
	
				if ($fh == $pool_listen) {								# listening socket, new connection
	
					my $new = $pool_listen->accept;							# accept connection
					$pool_select->add($new);								# add to active
	
					$miner_conn->{$new->fileno} = $miner_idx;						# add miners id number to hash of connections
	
					$miner->{$miner_idx}->{'state'} = $MINER_NEW;						# tag as new connection
					$miner->{$miner_idx}->{'type'}  = $MINER_TCP;						# connection type

					$miner->{$miner_idx}->{'fh'} = $new->fileno;

					$miner->{$miner_idx}->{'ipaddr'} = $new->peerhost;					# client IP address
					$miner->{$miner_idx}->{'connected'} = time;						# timestamps
					$miner->{$miner_idx}->{'updated'} = time;
					$miner->{$miner_idx}->{'block'} = 0;							# block number 
					$miner->{$miner_idx}->{'worknumber'} = 1;						# job number
	
					$miner_idx++;
				}
				else {
	
					my $id = $miner_conn->{$fh->fileno};							# get index number from connection hash
	
					my $buf = <$fh>;									# read socket

					print "$buf\n";


					my $req = common::read_json($buf);							# miner request
	
					if ($req->{'method'} eq 'mining.subscribe') {						# client connects to stratum
	
						print "PARSING : mining.subscribe\n";

						$miner->{$id}->{'software'} = $req->{'params'}[0];				# log mining software

						$miner->{$id}->{'nonce1'} = aes256::keyRandom(16);				# random nonce1 (16 hex-chars, 8-bytes)
	
						miner_write($fh, "\{\"id\":$req->{'id'},\"result\":\[null,\"$miner->{$id}->{'nonce1'}\"\],\"error\":null\}\n", $MINER_SUBSCRIBED);
					}
	
					elsif ($req->{'method'} eq 'mining.authorize') {					# username/password 
	
						print "PARSING : mining.authorize\n";

						if (common::addr_type($req->{'params'}[0]) eq 'saddr') {			# client username, payment address & MUST be a saddr
							$miner->{$id}->{'address'} = $req->{'params'}[0];
							miner_write($fh, "\{\"id\":$req->{'id'},\"result\": true,\"error\": null}\n", $MINER_IDLE); 

							new_work($id);								# give the new miner something to do	
						}
						else {
							miner_write($fh, "\{\"id\":$req->{'id'},\"result\": false,\"error\": \"Auth Failed\"}\n", $MINER_DISCONNECT);
						}
					}
	
					elsif ($req->{'method'} eq 'mining.extranonce.subscribe') {

						print "PARSING : mining.extranonce.subscribe\n";

						miner_write($fh, "\{\"id\":$req->{'id'},\"result\": false,\"error\": \"Not Supported\"}\n", $MINER_IDLE);
					}
	
					elsif ($req->{'method'} eq 'mining.submit') {						# client submits a share !
	
						print "PARSING : mining.submit\n";

						my $rawblock = $miner->{$id}->{'work'}->{'version'};
						$rawblock .= $miner->{$id}->{'work'}->{'previousblockhash'};
						$rawblock .= $miner->{$id}->{'work'}->{'merkleroot'};
						$rawblock .= $miner->{$id}->{'work'}->{'finalsaplingroothash'};
						$rawblock .= $req->{'params'}[2];
						$rawblock .= $miner->{$id}->{'work'}->{'bits'};
						$rawblock .= "$miner->{$id}->{'nonce1'}$req->{'params'}[3]";
						$rawblock .= $req->{'params'}[4];
						$rawblock .= $miner->{$id}->{'work'}->{'tx_data'};

						# TODO: Check solution & difficulty, if both tests pass the block can be submitted & we can play with lower targets
						
						my $resp = `$main::node_client submitblock $rawblock 2>/dev/null`;				# submit the block

						my $eval = eval { decode_json($resp) };

						if ($@) {											# non-json response

							if ($resp eq '') {									# accepted !
								miner_write($fh, "\{\"id\":$req->{'id'},\"result\": true\}\n", $MINER_IDLE);
								new_work();
							}
							else {											# rejected !
								miner_write($fh, "\{\"id\":$req->{'id'},\"result\": false\}\n", $MINER_IDLE);
							}
						}
						else {												# json response
							my $response = decode_json($resp);	

							if ($response->{'content'}->{'result'}->{'height'} == ($block->{'height'} + 1) ) {	# accepted
								miner_write($fh, "\{\"id\":$req->{'id'},\"result\": true\}\n", $MINER_IDLE);
								new_work();
							}
							else {											# rejected
								miner_write($fh, "\{\"id\":$req->{'id'},\"result\": false\}\n", $MINER_IDLE);
							}
						}
					}
					else {											# weird request, disconnect miner
						miner_disconnect($fh);
					}
				}
			}
		}

		my @miner_all = $pool_select->can_write(0);								# get handles for all connected miners
	
		foreach my $fh (@miner_all) {											# loop through & disconnect

			if ($fh != $pool_listen) {

				my $id = $miner_conn->{$fh->fileno};								# get index number from connection hash

				if ( (time - $miner->{$id}->{'updated'}) > $timer_timeout) {					# timed out

					$miner->{$id}->{'state'} = $MINER_DISCONNECTED;

					print "miner $id timed out!\n";
				}
				
				if ($miner->{$id}->{'state'} == $MINER_TARGETTED) {						# has target, send new work

					miner_write($fh, "\{\"id\":null,\"method\":\"mining.notify\",\"params\":\[\"$miner->{$id}->{'work'}->{'jobnumber'}\",\"$miner->{$id}->{'work'}->{'version'}\",\"$miner->{$id}->{'work'}->{'previousblockhash'}\",\"$miner->{$id}->{'work'}->{'merkleroot'}\",\"$miner->{$id}->{'work'}->{'finalsaplingroothash'}\",\"$miner->{$id}->{'work'}->{'time'}\",\"$miner->{$id}->{'work'}->{'bits'}\",true,\"ZcashPoW\"\]\}\n", $MINER_ACTIVE);

				}

				elsif ($miner->{$id}->{'state'} == $MINER_IDLE) {						# set target

					miner_write($fh, "\{\"id\":null,\"method\":\"mining.set_target\",\"params\":\[\"$miner->{$id}->{'work'}->{'target'}\"\]\}\n", $MINER_TARGETTED);
				}
				
				elsif ($miner->{$id}->{'state'} == $MINER_AUTHORIZED) {						# set target
					miner_write($fh, "\{\"id\":null,\"method\":\"mining.set_target\",\"params\":\[\"$miner->{$id}->{'work'}->{'target'}\"\]\}\n", $MINER_TARGETTED);

				}		
				elsif ($miner->{$id}->{'state'} == $MINER_ACTIVE) {						# mining, refresh if close to expiry

					if (time - $miner->{$id}->{'updated'} > $timer_interval) {

						miner_write($fh, "\{\"id\":null,\"method\":\"mining.notify\",\"params\":\[\"$miner->{$id}->{'work'}->{'jobnumber'}\",\"$miner->{$id}->{'work'}->{'version'}\",\"$miner->{$id}->{'work'}->{'previousblockhash'}\",\"$miner->{$id}->{'work'}->{'merkleroot'}\",\"$miner->{$id}->{'work'}->{'finalsaplingroothash'}\",\"$miner->{$id}->{'work'}->{'time'}\",\"$miner->{$id}->{'work'}->{'bits'}\",false,\"ZcashPoW\"\]\}\n", $MINER_ACTIVE);

						$miner->{$id}->{'updated'} = time;						# reset timestamp
					}
				}

				elsif ($miner->{$id}->{'state'} == $MINER_DISCONNECTED) {					# disconnect
					print "disconnecting miner $id\n";
					miner_disconnect($fh);
				}
			}
		}
	}
}	


#######################################################################################################################################
#
# Gracefull shutdown
#
sub shutdown {

	if ($running) {

		my @miner_all = $pool_select->can_write(0);								# get handles for all connected miners
	
		foreach my $fh (@miner_all) {											# loop through & disconnect
			if ($fh != $pool_listen) {
				miner_disconnect($fh);
			}
		}
		close ($pool_listen);											# close pool listening socket
	}
}


#######################################################################################################################################
#
# Disconnect mining client
#
sub miner_disconnect {

	my ($fh) = @_;

	$pool_select->remove($fh);											# remove from select
	
	delete ($miner_conn->{$fh});
	delete ($miner->{$miner->{$fh->fileno}});										# get index number from connection hash

	#	$fh->shutdown(2);													# close the socket
}


#######################################################################################################################################
#
# Send to mining client & update status
#
sub miner_write {


	my ($fh, $json, $state) = @_;

	print "$json\n";

	my $id = $miner_conn->{$fh->fileno};						# add miners id number to hash of connections

	$fh->write($json);

	$miner->{$id}->{'updated'} = time;											# update timestamp

	$miner->{$id}->{'state'} = $state;											# set miner state
}


1;	# all packages are true, even the ones that are not, especially the ones that are not

