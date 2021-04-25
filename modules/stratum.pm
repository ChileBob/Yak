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

#########################################################################################################################################################################
#
# CHANGING ANYTHING BELOW THIS LINE IS A REALLY BAD IDEA !! 
#
#########################################################################################################################################################################

use Data::Dumper;															# debugging

use IO::Handle;																# socket handlers for mining
use IO::Socket;
use IO::Select;

my $pool_listen;															# listening socket
my $pool_select;															# pool socket selector

my $devfee_address  = 's1YqPfBU6Z9MhnWrPkYBNtUaCzhjno1kKSP';										# ChileBob spends this on wine, women & song
my $devfee_percent  = 0.25;														# but...not much on song!

my $poolfee_address = '';
my $poolfee_percent = 0.25;														# Default pool fee

my $miner;																# hash of connected clients					
my $miner_conn;																# mining client connection hash
my $miner_idx = 0;															# mining client connection counter
my $miner_shares = {};															# count of shares

my $running = 0;

#######################################################################################################################################
#
# Start stratum server 
#
sub start {

	my ($port, $address, $fee) = @_;												# listening port number & pool address

	if ($address && $port) {

		$poolfee_address = $address;													# pool params 
		$poolfee_percent = 0 + $fee;											
	
		$pool_listen = IO::Socket::INET->new (												# open listening socket
			LocalPort => $port,
			Proto => 'tcp',
			Listen => SOMAXCONN,													# limit is approx 32k sockets, so plenty
			reuse => 1,
			Blocking => 0														# non-blocking socket
		);
	
		$pool_select = IO::Select->new($pool_listen);											# port select handler
	
		$running = 1;															# set runtime flag
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

	if ($running) {

		my ($template) = $_;

		common::debug($debug, "stratum::new_work()");

		#TODO: Send payouts
		#TODO: Oops..payment has to mature for 100 blocks before it can be used for payment
	
		$miner_shares = {};														# clear shares counter
	}
}

#######################################################################################################################################
#
# Check clients, read responses, send work, register shares, submit blocks
#
sub update {

	if ($running) {

		my @miner_ready = $pool_select->can_read(0); 							#TODO: MINING : Parse request from mining clients

		if (@miner_ready) {										# loop through all connections with requests
	
			foreach my $fh (@miner_ready) {
	
				if ($fh == $pool_listen) {							# listening socket, new connection
	
					my $new = $pool_listen->accept;						# accept connection
					$pool_select->add($new);						# add to active
	
					$miner_conn->{$new->fileno} = $miner_idx;				# add miners id number to hash of connections
	
					$miner->{$miner_idx}->{'fh'} = $new->fileno;				# set up new miner 
					$miner->{$miner_idx}->{'ipaddr'} = $new->peerhost;
					$miner->{$miner_idx}->{'connected'} = time;
					$miner->{$miner_idx}->{'updated'} = time;
					$miner->{$miner_idx}->{'block'} = 0;
					$miner->{$miner_idx}->{'target'} = 0;
					$miner->{$miner_idx}->{'jobnumber'} = 0;
	
					$miner_idx++;
				}
				else {
	
					my $id = $miner->{$fh->fileno};						# get index number from connection hash
	
					my $req = common::read_json(<$fh>);						# miner request
	
					if ($req->{'method'} eq 'mining.subscribe') {				# client connects to stratum
	
						$miner->{$id}->{'software'} = $req->{'params'}[0];		# log mining software
						$miner->{$id}->{'nonce1'} = aes256::keyRandom(16);		# random nonce1 (16 hex-chars, 8-bytes)
	
						miner_write($id, "\{\"id\":$req->{'id'},\"result\":\[null,\"$miner->{$id}->{'nonce1'}\"\],\"error\":null\}\n", $mining::CLIENT_SUBSCRIBED);
					}
	
					elsif ($req->{'method'} eq 'mining.authorize') {			# username/password 
	
						if (common::addr_type($req->{'params'}[0]) eq 'saddr') {	# client username, payment address & MUST be a saddr
							$miner->{$id}->{'address'} = $req->{'params'}[0];
							miner_write($id, "\{\"id\":$req->{'id'},\"result\": true,\"error\": null}\n", $mining::CLIENT_AUTHORIZED); 
						}
	
						else {
							miner_write($id, "\{\"id\":$req->{'id'},\"result\": false,\"error\": \"Auth Failed\"}\n", $mining::CLIENT_DISCONNECT);
						}
					}
	
					elsif ($req->{'method'} eq 'mining.extranonce.subscribe') {
						miner_write($id, "\{\"id\":$req->{'id'},\"result\": false,\"error\": \"Not Supported\"}\n", $mining::CLIENT_AUTHORIZED);
	
					}
	
					elsif ($req->{'method'} eq 'mining.submit') {				# client submits a share !
	
						# TODO: Check solution
						#
						# - if valid equihash :-
						# 	increase client share count, 
						# 	acknowledge share	
						#
						# 	check difficulty against target
						# 	if good
						# 		submit block
						# 		parse node response
						# 		if accepted
						# 			tag all active miners as IDLE
						#
						# - if not valid equihash :-
						# 	reject the share
						
	
						# TODO: Tell miner success/fail
						# miner_write($id, "\{\"id\":$req->{'id'},\"result\": true,\"error\": null}\n", $mining::CLIENT_IDLE); 
						# miner_write($id, "\{\"id\":$req->{'id'},\"result\": false,\"error\": \"Rejected\"}\n", $mining::CLIENT_ACTIVE);
						# 	
						# foreach my $idx (keys %$miner) {					# all active miners need new work
						# 	if ($miner->{$idx}->{'state'} = $mining::CLIENT_ACTIVE) {
						#		$miner->{$idx}->{'state'} = $mining::CLIENT_IDLE;
						# 	}
						# }
	
					}
					else {									# weird request, disconnect miner
						miner_disconnect($fh);
					}
				}
			}
		}
	
		# TODO: TARGETTED -> ACTIVE			(generate & send new work)
		# TODO: IDLE -> TARGETED			(send target)
		# TODO: SUBSCRIBED -> TARGETED			(send target)
		# TODO: ACTIVE -> SUBSCRIBED			(when block mined & accepted)
		
		# TODO: AUTHORISED & expired -> DISCONNECTING
		# TODO: SUBSCRIBED & expired -> DISCONNECTING
		# TODO: DISCONNECTED need DISCONNECTING
	}
}	


#######################################################################################################################################
#
# Time based tasks go here
#
sub interval_timer {

	if ($running) {

		# TODO: Prevent miners from timing out
	}	
}


#######################################################################################################################################
#
# Gracefull shutdown
#
sub shutdown {

	if ($running) {
		my @miner_all = $pool_select->can_write(0);											# get handles for all connected miners
	
		foreach my $fh (@miner_all) {													# loop through & disconnect
			if ($fh != $pool_listen) {
				miner_disconnect($fh);
			}
		}
		close ($pool_listen);														# close pool listening socket
	}
}


#######################################################################################################################################
#
# Disconnect mining client
#
sub miner_disconnect {

	my ($fh) = @_;

	$pool_select->remove($fh);
	$fh->shutdown(2);
}


#######################################################################################################################################
#
# Send to mining client & update status
#
sub miner_write {

	my ($id, $json, $state) = @_;

	$miner->{$id}->{'fh'}->write($json);

	$miner->{$id}->{'updated'} = time;
	$miner->{$id}->{'state'} = $state;
}

1;
