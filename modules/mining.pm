#!/usr/bin/perl
#
# yak : mining subs
#
# MIT License (ChileBob)
#
# Zcash : zs1a7qnkg8hr74ujj08jhjcdfs7s62yathqlyn5vd2e8ww96ln28m3t2jkxun5fp7hxjntcg8ccuvs
# Ycash : ys17fsj64ydl93net807xr00ujz2lnrf22cjf4430vvz69vpaat8t3hrdjmkvj7thrw4fdaz7l0pns

package mining;

use Data::Dumper;
use Bitcoin::Crypto::Base58 qw(:all);
use Digest::SHA qw(sha256);

my $debug = 5;						# global debug verbosity, 0 = quiet
							
our $CLIENT_NEW         = 0x00;				# - new connection
our $CLIENT_SUBSCRIBED  = 0x01;				# - subscribed
our $CLIENT_AUTHORIZED  = 0x02;				# - authenticated
our $CLIENT_IDLE        = 0x10;				# - idle
our $CLIENT_TARGETED    = 0x11;				# - targetted
our $CLIENT_ACTIVE      = 0x12;				# - active (mining)
our $CLIENT_DISCONNECT  = 0xff;				# - disconnected


#########################################################################################################################################################################
#
# verify solution matches the required difficulty
#
sub verify_difficulty {

	my ($header, $nonce, $solution, $nbits) = @_;							# hex-encoded strings, endian-ness as per block header

	my $target = nbits_to_target($nbits);								# convert nbits to 256-bit target
	$target =~ s/0*$//;										# strip training zeros

	my $diff = unpack("H*", reverse sha256(sha256(pack("H*", $header . $nonce . $solution)))); 	# get hex-encoded double-sha256 of the block header
	$diff = substr($diff, 0, length($target));							# cut to length of significant target bytes

	if (hex($diff) < hex($target) ) {								# difficulty must be less or equal to target
		return(1);		
	}
}

#########################################################################################################################################################################
#
# verify block header & equihash solution 								Based on : https://git.hush.is/hush/hushwebminer/src/branch/master/pool-emu/equihash.pm
#
sub verify_equihash {

	my ($header, $nonce, $solution, $N, $K) = @_;							# hex-encoded strings, endian-ness as per block header, equihash N & K integers
													#
	my $bpi = ($N / ($K + 1)) + 1;									# bits per index	200/9 = 21       192/7 = 25
	my $indexes = 2**$K;										# number of indexes	200/9 = 512      192/7 = 128
	my $hashlen = $N / 4;										# blake2b hash length	200/9 = 50       192/7 = 48
	my $solsize = ($bpi * $indexes) / 8;								# solution size		200/9 = 1344, 192/7 = 400

	if ( $solsize != readCompactSize(substr($solution, 0, 6))) {					# check solution size
		return(0);
	}

	$header   = pack("H*", $header);								# convert args to binary
	$nonce    = pack("H*", $nonce);
	$solution = pack("H*", substr($solution, 6));

	my @sol = map { oct "0b$_" } unpack "(a$bpi)*", unpack 'B*', $solution;				# extract indexes from solution
	@sol == $indexes or return(0);
									
	my %uniq; 											# check indexes are unique
	@uniq{@sol} = (); 
	keys %uniq == $indexes or return(0);

	for my $step (1..$K) {										# check indexes are ordered
		my $off = 2**($step-1);
		$sol[$_] < $sol[$_+$off] or return(0)
		for map $_*$off*2, 0 .. 2**($K-$step)-1;
	}
													# setup blake2b
	my $blake = blake2b::new ( hashlen  => $hashlen, personal => ('ZcashPoW' . pack 'VV', $N, $K),	)->update ($header . $nonce);

	@sol = map {											# get hashes
		my $bl = $blake->copy ()->final (pack 'V', $_ / 2);
		length $bl == $hashlen or return(0);
		substr $bl, $_ % 2 * ($hashlen/2), ($hashlen/2)	
	} @sol;

	for my $step (1..$K) {										# XOR hashes
		@sol = map $sol[$_*2] ^ $sol[$_*2+1], 0 .. @sol/2 - 1;
		unpack ('B' . $step * 20, $_) =~ /^0+\z/ or return(0) for @sol;
	}
	@sol == 1 or return(0);

	if ( hex(unpack("H*", $sol[0])) == 0) {								# valid if final XOR is zero
		return(1);
	}
}


#########################################################################################################################################################################
#
# generate a hex-encoded coinbase transaction
#
sub make_coinbase {

	my ($template, $outputs) = @_;

	my @outputs = @{$outputs};									# dereference outputs

	my $coinbase = substr($template->{'coinbasetxn'}->{'data'}, 0, 110);				# transaction header & coinbase input

	my $txn_out = txn_out( $template->{'coinbasetxn'}->{'foundersaddress'}, $template->{'coinbasetxn'}->{'foundersreward'});

	my $reward = block_reward($template->{'coinbasetxn'}->{'data'}) - $template->{'coinbasetxn'}->{'foundersreward'};

	my $payout_addr;
	foreach my $out (@outputs) {

		if (!exists $out->{'percent'}) {							# no percentage, gets remaining block reward
			$payout_addr = $out->{'address'};
		}
		else {											# fixed percentage, generate output
			my $amount = int (($out->{'percent'} * $reward) / 100);	# reduce remaining reward
			$txn_out .= txn_out( $out->{'address'}, $amount);
			$reward -= $amount;
		}
	}
	$txn_out .= txn_out( $payout_addr, $reward);							# last txn is the remaining reward

	$txn_out .= '00000000000000000000000000000000000000';						# final parts of txn

	return($coinbase . hexCompactSize(scalar @outputs + 1) . $txn_out);
}


#########################################################################################################################################################################
#
# convert nBits into target, all as hex-encoded strings
#
sub nbits_to_target {

	my ($nbits) = @_;										# hex-encoded nBits

	my $target = substr($nbits,2,6);								# most significant bits

	my $exp = hex(substr($nbits,0,2)) - 3;								# exponent
	while ($exp > 0) {								 
		$target .= '00';
		$exp--;
	}
	while (length($target) < 64) {									# leading zeros
		$target = '00' . $target;
	}
	return($target);										# return target
}


#########################################################################################################################################################################
#
# generate hex-encoded transparent output given the payment address & amount (zats)
#
sub txn_out {

	my ($address, $zats) = @_;									# payment address, amount in zats

	print "txn_out() : $address, $zats\n";

	my $amount = unpack("H*", reverse pack("H*", sprintf("%016X", $zats)));				# 8-bytes, little-endian

	my $script = addr_to_script($address);								# raw script

	return($amount . $script);
}

#########################################################################################################################################################################
#
# get hex-encoded payment script bytes from address
#
sub addr_to_script {

	my ($address) = @_;										# payment address

	my $payhash = unpack("H*", substr(decode_base58check($address),2));				# raw script

	if ( $address =~ m/^.1/) {									# pay to t1/s1

		return($payhash = '1976a914' . $payhash . '88ac');

	}
	elsif ( $address =~ m/^.3/) {									# pay to t3/s3

		return($payhash = 'a914' . $payhash . '87');
	}
}


#########################################################################################################################################################################
#
# get block reward from hex-encoded coinbase transaction
#
sub block_reward {

	my ($hexData) = @_;										# coinbase transaction as hex-encoded string

	my $blockReward = 0;										# block reward

	my $hexOutputs = substr($hexData, 112, -36);							# transaction outputs

	while (length($hexOutputs) > 0) {								# loop through all outputs

		$blockReward += hex(reverse_bytes(substr($hexOutputs, 0, 16)));				# add value to block reward total
		$hexOutputs = substr($hexOutputs, (18 + (2 * readCompactSize(substr($hexOutputs, 16, 10)))));	
	}

	return($blockReward);										# block reward in zats
}


#########################################################################################################################################################################
#
# return compactSize as hex-encoded little-endian string for an integer or hex-encoded encoded data
#
sub hexCompactSize {					

	my $length;
	my $compact = '';

	my ($hexData, $type) = @_;

	if ($type eq 's') {
		$length = length($hexData) / 2;								# hex string, convert to length in bytes
	}
	elsif ($type eq 't') {
		$length = (length($hexData) / 2) + 1;							# transaction, hex-string length plus 1
	}
	else {												# integer 
		$length = $hexData;
	}

	if ($length < 253) {										# 8-bit (happens all the time)
		$compact = sprintf("%02x", $length);
	        return($compact);
	}
	elsif ( ($length >= 253) && ($length <= 65535) ) {						# 16-bit (happens sometimes)
		$compact = sprintf("%04x", $length);
		$compact = reverse_bytes($compact);
		return("fd$compact");
	}
	elsif ( ($length > 65556) && ($length <= 4294967295)) {						# 32-bit (never happened, not likely either)
		$compact = sprintf("%08x", $length);
		$compact = reverse_bytes($compact);
		return("fe$compact");
	}
	else {												# 64-bit (you gotta be kidding!! but just for completeness)
		$compact = sprintf("%016x", $length);
		$compact = reverse_bytes($compact);
		return("ff$compact");
	}
}

#########################################################################################################################################################################
#
# read compactSize hex-encoded bytes, return integer
#
sub readCompactSize {

	my ($hexData) = @_;

	if ( substr($hexData,0,2) eq 'fd') {	
		return(hex(reverse_bytes(substr($hexData,2,4))));
	}
	elsif ( substr($hexData,0,2) eq 'fe') {
		return(hex(reverse_bytes(substr($hexData,2,8))));
	}
	elsif ( substr($hexData,0,2) eq 'ff') {
		return(hex(reverse_bytes(substr($hexData,2,16))));
	}
	else {				
		return(hex(substr($hexData,0,2)));
	}
}

#########################################################################################################################################################################
#
# generate merkleroot from transaction txids
#
sub merkleroot {				

	my @hashes = ();

	foreach (@{$_[0]}) {										# dereference, data is hex-encoded
		push @hashes, $_;									# txids are little-endian
	}

	if ( (scalar @hashes) == 1 ) {									# if its an empty block (1 tx)
		return($hashes[0]);									# return coinbase txn hash as merkleroot
	}

	while ((scalar @hashes) > 1) {									# loop through array until there's only one value left

		if ( ((scalar @hashes) % 2) != 0 )  {							# duplicate last hash if there's an odd number
			push @hashes, $hashes[((scalar @hashes) - 1)];
		}

		my @joinedHashes;

		while (my @pair = splice @hashes, 0, 2) {						# get a pair of hashes
			push @joinedHashes, hash_this(reverse_bytes("$pair[1]$pair[0]"));		# get the hash
		}
		@hashes = @joinedHashes;								# replace hashes with joinedHashes
	}
	return($hashes[0]);										# returns hex-encoded big-endian
}


#########################################################################################################################################################################
#
# hash hex-encoded transaction data
#
sub hash_this {						

	my ($hexData) = @_;										# hex-encoded transaction data

	return(unpack("H*", reverse sha256(sha256(pack "H*", $hexData))));				# returns hash, hex-encoded, little-endian
}


#########################################################################################################################################################################
#
# reverse byte order of hex-encoded string
#
sub reverse_bytes {											# reverse byte order of a hex-encoded string

	my ($hexString) = @_;

	return( unpack("H*", reverse pack("H*", $hexString))) ;
}

