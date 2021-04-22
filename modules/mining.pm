#!/usr/bin/perl
#
# mining subs
#
# MIT License (ChileBob)
#
# Zcash : zs1a7qnkg8hr74ujj08jhjcdfs7s62yathqlyn5vd2e8ww96ln28m3t2jkxun5fp7hxjntcg8ccuvs
# Ycash : ys17fsj64ydl93net807xr00ujz2lnrf22cjf4430vvz69vpaat8t3hrdjmkvj7thrw4fdaz7l0pns

package mining;

use Data::Dumper;
use Bitcoin::Crypto::Base58 qw(:all);

my $debug = 5;						# global debug verbosity, 0 = quiet

#########################################################################################################################################################################
#
# convert nBits into target, all as hex-encoded strings
#
sub nbits_to_target {

	my ($nbits) = @_;								# hex-encoded nBits

	my $target = substr($nbits,2,6);						# most significant bits

	my $exp = hex(substr($nbits,0,2)) - 3;						# exponent
	while ($exp > 0) {								 
		$target .= '00';
		$exp--;
	}
	while (length($target) < 64) {							# leading zeros
		$target = '00' . $target;
	}
	return($target);								# return target
}

#########################################################################################################################################################################
#
# generate hex-encoded transparent output given the payment address & amount (zats)
#
sub txn_out {

	my ($address, $zats) = @_;							# payment address, amount in zats

	my $amount = unpack("H*", reverse pack("H*", sprintf("%016X", $zats)));		# 8-bytes, little-endian

	my $script = unpack("H*", substr(decode_base58check($address),2));		# raw script

	if ( $address =~ m/^.1/) {							# pay to t1/s1
		return($amount . '76a91419' . $script . '88ac');
	}
	elsif ( $address =~ m/^.3/) {							# pay to t3/s3
		return($amount . 'a91417' . $script . '87');
	}
}


#########################################################################################################################################################################
#
# get block reward from hex-encoded coinbase transaction
#
sub blockReward {

	my ($hexData) = @_;								# coinbase transaction as hex-encoded string

	my $blockReward = 0;								# block reward

	my $hexOutputs = substr($hexData, 112, -36);					# transaction outputs

	while (length($hexOutputs) > 0) {						# loop through all outputs

		$blockReward += hex(reverse_bytes(substr($hexOutputs, 0, 16)));		# add value to block reward total
		$hexOutputs = substr($hexOutputs, (18 + (2 * readCompactSize(substr($hexOutputs, 16, 10)))));	
	}

	return($blockReward);								# block reward in zats
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
		$length = length($_[0]) / 2;									# hex string, convert to length in bytes
	}
	else {													# integer 
		$length = $_[0];
	}

	if ($length < 253) {											# 8-bit
		$compact = sprintf("%02x", $length);
	        return($compact);
	}
	elsif ( ($length >= 253) && ($length <= 65535) ) {							# 16-bit
		$compact = sprintf("%04x", $length);
		$compact = reverse_bytes($compact);
		return("fd$compact");
	}
	elsif ( ($length > 65556) && ($length <= 4294967295)) {							# 32-bit
		$compact = sprintf("%08x", $length);
		$compact = reverse_bytes($compact);
		return("fe$compact");
	}
	else {													# 64-bit
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
	else {							# works !
		return(hex(substr($hexData,0,2)));
	}
}

#########################################################################################################################################################################
#
# generate merkleroot from transaction txids
#
sub merkleroot {				

	my @hashes = ();

	foreach (@{$_[0]}) {											# dereference, data is hex-encoded
		push @hashes, $_;										# txids are little-endian
	}

	if ( (scalar @hashes) == 1 ) {										# if its an empty block (1 tx)
		return($hashes[0]);										# return coinbase txn hash as merkleroot
	}

	while ((scalar @hashes) > 1) {										# loop through array until there's only one value left

		if ( ((scalar @hashes) % 2) != 0 )  {								# duplicate last hash if there's an odd number
			push @hashes, $hashes[((scalar @hashes) - 1)];
		}

		my @joinedHashes;

		while (my @pair = splice @hashes, 0, 2) {							# get a pair of hashes
			push @joinedHashes, hash_this(reverse_bytes("$pair[1]$pair[0]"));			# get the hash
		}
		@hashes = @joinedHashes;									# replace hashes with joinedHashes
	}
	return($hashes[0]);											# returns hex-encoded big-endian
}


#########################################################################################################################################################################
#
# hash hex-encoded transaction data
#
sub hash_this {						

	my ($hexData) = @_;											# hex-encoded transaction data

	return(unpack("H*", reverse sha256(sha256(pack "H*", $hexData))));					# returns hash, hex-encoded, little-endian
}


#########################################################################################################################################################################
#
# reverse byte order of hex-encoded string
#
sub reverse_bytes {												# reverse byte order of a hex-encoded string

	my ($hexString) = @_;

	return( unpack("H*", reverse pack("H*", $hexString))) ;
}

