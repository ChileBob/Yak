#!/usr/bin/perl
#
# yak : stratum mining
#
# MIT License (ChileBob)
#
# Zcash : zs1a7qnkg8hr74ujj08jhjcdfs7s62yathqlyn5vd2e8ww96ln28m3t2jkxun5fp7hxjntcg8ccuvs
# Ycash : ys17fsj64ydl93net807xr00ujz2lnrf22cjf4430vvz69vpaat8t3hrdjmkvj7thrw4fdaz7l0pns

package stratum;

my $debug = 0;															# debug verbosity for this package

our $pool_listen;
our $pool_select;

our $pool_target = '007ffff000000000000000000000000000000000000000000000000000000000';						# pool target, all miners get the same
our $pool_sols   = 0;														# guestimated sols/s	(shares per min x 8.628)

our $MINER_DISCONNECT  = 0;		# - disconnected

our $MINER_NEW         = 1;		# - new connection
our $MINER_SUBSCRIBED  = 2;		# - subscribed

our $MINER_AUTHORIZED  = 3;		# - authenticated
our $MINER_IDLE        = 16;		# - idle
our $MINER_TARGETTED   = 17;		# - targetted
our $MINER_ACTIVE      = 18;		# - active (mining)


my $MINER_TCP = 1;			# direct connection
my $MINER_WEB = 2;			# via websocket

#########################################################################################################################################################################
#
# CHANGING ANYTHING BELOW THIS LINE IS A REALLY BAD IDEA !! 
#
#########################################################################################################################################################################

use Data::Dumper;														# debugging

use IO::Handle;															# socket handlers for mining
use IO::Socket;
use IO::Select;

use File::Path qw(make_path);													# create spool directories
use YAML qw(DumpFile);														# write miner shares to spool directory
use Digest::SHA qw(sha256);													# hash miner solutions to prevent duplicates

my $devfee_address  = 's1YqPfBU6Z9MhnWrPkYBNtUaCzhjno1kKSP';									# ChileBob spends this on wine, women & song
our $devfee_percent = 0.5;													# .....not much on song! :-)

my $pool_percent     = 0;													# default pool fee is zero, set by stratum::init()
my $pool_transparent = '';													# transparent address we mine to
my $pool_spool;															# spool dir for mining shares

my $pool_shares     = 0;													# shares per minute (approx)

my $template;

my $miner;															# miner (config/state)
my $miner_conn;															# miner (connection hash)

my $miner_share;														# miner shares for the current block
my @share_hashes;														# hash of shares (prevent duplicates)

my $miner_idx = 1;														# miner client counter

my $running = 0;														# runtime flag

my $timer_interval = 30;													# timer reset (seconds), refresh miner tasks
my $timer_timeout = 60;														# timeout (seconds), clients inactive for this long are disconnected
my $timer_lastcalled = time;													# last time the timer interval was called

#######################################################################################################################################
#
# Start stratum server 
#
sub start {

	my ($port, $address, $fee) = @_;											# listening port number & pool address

	if ($address && $port) {

		$pool_transparent = $address;											# pool params 
		$pool_percent = 0 + $fee;											
	
		$pool_listen = IO::Socket::INET->new (										# open listening socket
			LocalPort => $port,
			Proto => 'tcp',
			Listen => SOMAXCONN,											# limit is approx 32k sockets, so plenty
			Reuse => 1,
			Blocking => 0												# non-blocking socket
		);
	
		$pool_select = IO::Select->new($pool_listen);									# port select handler

		clear_shares();
		@share_id = ();
	
		$running = 1;													# set runtime flag

		make_path("$main::install/spool/unpaid/$pool_transparent");							# create spool dir for share records
	}
	else {
		common::debug(0,"Failed to start stratum pool.");
		exit(1);
	}
}

#######################################################################################################################################
#
# things to do when a new block starts
#
sub new_block {

	DumpFile("$main::install/spool/unpaid/$pool_transparent/$template->{'height'}", $miner_share);					# write miner shares to spool dir

	clear_shares();
	@share_id = ();

	new_work();															# new work for all miners
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

		$template = common::node_cli('getblocktemplate', '', '');								# refresh the block template

		foreach my $id (@miner_id) {

			if ($miner->{$id}->{'state'} >= $MINER_AUTHORIZED) {								# only for miners that are ready to work

				$miner->{$id}->{'work'}->{'tx_data'} = mining::make_coinbase($template, [ 				# generate coinbase transaction
					{ address => $devfee_address, percent => $devfee_percent},					# - devfee mined in coinbase
					{ address => $pool_transparent }								# - balance to pool transparent address
				]);
	
				my @tx_id = mining::hash_this($miner->{$id}->{'work'}->{'tx_data'});					# coinbase txid
	
				my $txn_count = 1;
				foreach my $tx ( @{$template->{'transactions'}} ) {							# add remaining transactions
					push @tx_id, $tx->{'hash'};
					$miner->{$id}->{'work'}->{'tx_data'} .= $tx->{'data'};
					$txn_count++;
				}

				$miner->{$id}->{'work'}->{'tx_data'} = mining::hexCompactSize($txn_count) . $miner->{$id}->{'work'}->{'tx_data'};	# prefix transaction data with txn count

				$miner->{$id}->{'work'}->{'target'} = $pool_target;								# fixed pool target
	
				$miner->{$id}->{'work'}->{'version'}    	  = unpack("H*", pack("L", $template->{'version'}));		# version    (little-endian)
				$miner->{$id}->{'work'}->{'merkleroot'} 	  = mining::reverse_bytes(mining::merkleroot(\@tx_id));		# merkleroot (little-endian)
				$miner->{$id}->{'work'}->{'previousblockhash'} 	  = mining::reverse_bytes($template->{'previousblockhash'});	# previousblockhash (little-endian)
				$miner->{$id}->{'work'}->{'finalsaplingroothash'} = mining::reverse_bytes($template->{'finalsaplingroothash'});	# finalsaplingroothash (little-endian)
				$miner->{$id}->{'work'}->{'time'} 		  = unpack("H*", pack("L", time));				# epoch time (little-endian)
				$miner->{$id}->{'work'}->{'bits'} 		  = mining::reverse_bytes($template->{'bits'});			# block minimum difficulty (little-endian)
	
				$miner->{$id}->{'work'}->{'jobnumber'}++;									# increment job number
				$miner->{$id}->{'work'}->{'shares'} = 0;									# clear share counter
	
				if ( $miner->{$id}->{'state'} > $MINER_TARGETTED ) { 						# tag miner as idle
					$miner->{$id}->{'state'} = $MINER_TARGETTED;	
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
					
					if ($buf) {

						my $req = common::read_json($buf);							# miner request
		
						if ($req->{'method'} eq 'mining.subscribe') {						# client connects to stratum
		
							$miner->{$id}->{'software'} = $req->{'params'}[0];				# log mining software
	
							$miner->{$id}->{'nonce1'} = aes256::keyRandom(16);				# random nonce1 (16 hex-chars, 8-bytes)
		
							miner_write($fh, "\{\"id\":$req->{'id'},\"result\":\[null,\"$miner->{$id}->{'nonce1'}\"\],\"error\":null\}\n", $MINER_SUBSCRIBED);
						}
		
						elsif ($req->{'method'} eq 'mining.authorize') {					# username/password 
		
							if ( common::addr_type($req->{'params'}[0]) ) {					# client username, payment address can be any ycash/zcash type
	
								$miner->{$id}->{'address'} = $req->{'params'}[0];
								miner_write($fh, "\{\"id\":$req->{'id'},\"result\": true,\"error\": null}\n", $MINER_IDLE); 
							}
							else {
								miner_write($fh, "\{\"id\":$req->{'id'},\"result\": false,\"error\": \"Auth Failed\"}\n", $MINER_DISCONNECT);
							}
						}
		
						elsif ($req->{'method'} eq 'mining.extranonce.subscribe') {
	
							miner_write($fh, "\{\"id\":$req->{'id'},\"result\": false,\"error\": \"Not Supported\"}\n", $miner->{$id}->{'state'});
						}
		
						elsif ($req->{'method'} eq 'mining.submit') {						# client submits a share !
		
							my $header = $miner->{$id}->{'work'}->{'version'};				# block header
							$header .= $miner->{$id}->{'work'}->{'previousblockhash'};
							$header .= $miner->{$id}->{'work'}->{'merkleroot'};
							$header .= $miner->{$id}->{'work'}->{'finalsaplingroothash'};
							$header .= $req->{'params'}[2];
							$header .= $miner->{$id}->{'work'}->{'bits'};
	
							my $nonce    = "$miner->{$id}->{'nonce1'}$req->{'params'}[3]";			# nonce
							my $solution = $req->{'params'}[4];						# solution
	
							
							my $share_hash = unpack("H*", sha256(sha256(pack("H*", $solution)))); 						# prevent duplicate shares
							if (grep(/$share_hash/, @share_hashes)) {		

								# print "\nDUPLICATE SHARE!\n";
								miner_write($fh, "\{\"id\":$req->{'id'},\"result\": false\}\n", $MINER_TARGETTED);			# kill naughty miners ?
							}
							else {
								push @share_hashes, $share_hash;									# store this solution hash
	
								my $diff = mining::verify_difficulty($header, $nonce, $solution, $template->{'bits'}, $pool_target);	# check difficulty
								
								if ($diff == 1) {											# possible share !!

									if ( mining::verify_equihash($header, $nonce, $solution, 192, 7) ) {				# check equihash solution

										$miner_share->{$miner->{$id}->{'address'}}++;						# add to shares
										$pool_shares++;										# increment pool share counter
										miner_write($fh, "\{\"id\":$req->{'id'},\"result\": true\}\n", $MINER_ACTIVE);
									}
									else {												# bad solution, reject share
										# print "\nBAD SOLUTION!\n";
										miner_write($fh, "\{\"id\":$req->{'id'},\"result\": false\}\n", $MINER_ACTIVE);
									}
								}

								elsif ($diff == 2) {											# possible block !!!

									if ( mining::verify_equihash($header, $nonce, $solution, 192, 7) ) {				# check equihash solution
		
										my $rawblock = $header . $nonce . $solution . $miner->{$id}->{'work'}->{'tx_data'};		# add transaction data
								
										my $resp = `$main::node_client submitblock $rawblock 2>&1`;					# submit the block
					
										my $eval = eval { decode_json($resp) };
				
										if ($@) {											# non-json response
					
											if ($resp eq '') {									# block accepted !
												print "\nFOUND BLOCK!\n";
												$miner_share->{$miner->{$id}->{'address'}}++;					# add to shares
												$pool_shares++;									# increment pool share counter
												miner_write($fh, "\{\"id\":$req->{'id'},\"result\": true\}\n", $MINER_ACTIVE);
												new_work();
											}
											else {											# block rejected !
												print "\nREJECTED BLOCK!\n";
												miner_write($fh, "\{\"id\":$req->{'id'},\"result\": false\}\n", $MINER_ACTIVE);
											}
										}
										else {												# json response (happens sometimes)
											my $response = decode_json($resp);	
				
											if ($response->{'content'}->{'result'}->{'height'} == ($block->{'height'} + 1) ) {	# block accepted
												print "\nFOUND BLOCK! (1)\n";
												$miner_share->{$miner->{$id}->{'address'}}++;					# add to shares
												$pool_shares++;									# increment pool share counter
												miner_write($fh, "\{\"id\":$req->{'id'},\"result\": true\}\n", $MINER_ACTIVE);
												new_work();
											}
											else {											# block rejected
												print "\nREJECTED BLOCK! (1)\n";
												miner_write($fh, "\{\"id\":$req->{'id'},\"result\": false\}\n", $MINER_ACTIVE);
											}
										}
									}
								}
								else {	# bad share, not difficult enough

									print "\nDIFFICULTY LOWI!!\n";
									miner_write($fh, "\{\"id\":$req->{'id'},\"result\": false\}\n", $MINER_IDLE);
								}
							}
						}
						else {											# weird request, disconnect miner
							miner_disconnect($fh);
						}
					}
					else {
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

					$miner->{$id}->{'state'} = $MINER_DISCONNECT;
				}
				
				if ($miner->{$id}->{'state'} == $MINER_TARGETTED) {						# has target, send new work

					new_work($id);

					miner_write($fh, "\{\"id\":null,\"method\":\"mining.notify\",\"params\":\[\"$miner->{$id}->{'work'}->{'jobnumber'}\",\"$miner->{$id}->{'work'}->{'version'}\",\"$miner->{$id}->{'work'}->{'previousblockhash'}\",\"$miner->{$id}->{'work'}->{'merkleroot'}\",\"$miner->{$id}->{'work'}->{'finalsaplingroothash'}\",\"$miner->{$id}->{'work'}->{'time'}\",\"$miner->{$id}->{'work'}->{'bits'}\",true,\"ZcashPoW\"\]\}\n", $MINER_ACTIVE);
					$miner->{$id}->{'updated'} = time;							# reset timestamp

				}

				elsif ($miner->{$id}->{'state'} == $MINER_IDLE) {						# set target

					miner_write($fh, "\{\"id\":null,\"method\":\"mining.set_target\",\"params\":\[\"$pool_target\"\]\}\n", $MINER_TARGETTED);
					$miner->{$id}->{'updated'} = time;							# reset timestamp
				}
				
				elsif ($miner->{$id}->{'state'} == $MINER_AUTHORIZED) {						# set target

					miner_write($fh, "\{\"id\":null,\"method\":\"mining.set_target\",\"params\":\[\"$pool_target\"\]\}\n", $MINER_TARGETTED);

					new_work($id);

					$miner->{$id}->{'updated'} = time;							# reset timestamp
				}		

				elsif ($miner->{$id}->{'state'} == $MINER_ACTIVE) {						# mining, refresh if close to expiry

					if ( (time - $miner->{$id}->{'updated'}) > $timer_interval) {

						miner_write($fh, "\{\"id\":null,\"method\":\"mining.notify\",\"params\":\[\"$miner->{$id}->{'work'}->{'jobnumber'}\",\"$miner->{$id}->{'work'}->{'version'}\",\"$miner->{$id}->{'work'}->{'previousblockhash'}\",\"$miner->{$id}->{'work'}->{'merkleroot'}\",\"$miner->{$id}->{'work'}->{'finalsaplingroothash'}\",\"$miner->{$id}->{'work'}->{'time'}\",\"$miner->{$id}->{'work'}->{'bits'}\",false,\"ZcashPoW\"\]\}\n", $MINER_ACTIVE);

						$miner->{$id}->{'updated'} = time;						# reset timestamp
					}
				}

				elsif ($miner->{$id}->{'state'} == $MINER_DISCONNECT) {						# disconnect
					miner_disconnect($fh);
				}
			}
		}
	}

	timer_interval();													# time related activities
}	


#######################################################################################################################################
#
# Gracefull shutdown
#
sub shutdown {

	if ($running) {

		my @miner_all = $pool_select->can_write(0);								# get handles for all connected miners
	
		foreach my $fh (@miner_all) {										# loop through & disconnect
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

	my $id = $miner_conn->{$fh->fileno};							# get index number from connection hash
	
	$pool_select->remove($fh);											# remove from select
	
	delete ($miner_conn->{$fh});
	delete ($miner->{$id} );											# get index number from connection hash

	$fh->shutdown(2);												# close the socket
}


#######################################################################################################################################
#
# Send to mining client & update status
#
sub miner_write {

	my ($fh, $json, $state) = @_;

	my $id = $miner_conn->{$fh->fileno};							# add miners id number to hash of connections

	$fh->write($json);

	$miner->{$id}->{'state'} = $state;										# set miner state
	$miner->{$id}->{'updated'} = time;										# reset timestamp
}


#######################################################################################################################################
#
# Clear all shares from hash, 
#
sub clear_shares {

	for my $key (keys %$miner_share) {
		delete ($miner_share->{$key});
	}
}


#######################################################################################################################################
#
# Timed events
#
sub timer_interval {

	if ( (time - $timer_lastcalled) >= 60) {										# no more than once a minute

		$pool_sols = int ($pool_sols + (($pool_shares * 8.5) / ((time - $timer_lastcalled)/ 60))) / 2;		# guestimate pool hashrate
		$pool_shares = 0;

		print "\n";
		print "Hashrate : $pool_sols Sols/s\n";
		print "Miners   : " . scalar $pool_select->can_write(0) . "\n";						# number of connected miners
		print "\n";

		$timer_lastcalled = time;										# reset lastcalled timestamp to now
	}
}

1;	# all packages are true, even the ones that are not, especially the ones that are not

