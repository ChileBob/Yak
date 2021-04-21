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
# generate a transparent transaction output given the address & amoount in zats
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
# return compactSize for an integer or hex-encoded encoded data
#
sub compact_size {					

	my $length;
	my $compact = '';

	if ($_[1] eq 's') {
		$length = length($_[0]) / 2;									# hex string, convert to length in bytes
	}
	else {													# integer 
		$length = $_[0];
	}

	if ($length < 253) {											# 8-bit
		$compact = sprintf("%02x", $length);
	        return($compact);
	}
	elsif ( ($length >= 253) && ($length <= 65535) ) {							# 16-bit, little-endian
		$compact = sprintf("%04x", $length);
		$compact = reverse_bytes($compact);
		return("fd$compact");
	}
	elsif ( ($length > 65556) && ($length <= 4294967295)) {							# 32-bit, little-endian
		$compact = sprintf("%08x", $length);
		$compact = reverse_bytes($compact);
		return("fe$compact");
	}
	else {													# 64-bit, little-endian
		$compact = sprintf("%016x", $length);
		$compact = reverse_bytes($compact);
		return("ff$compact");
	}
}

#########################################################################################################################################################################
#
# generate merkleroot from array-ref of transactions ids
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
			push @joinedHashes, hash_this(reverse_bytes("$pair[1]$pair[0]"), 'le');			# get the hash
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

	if ($_[1] eq 'le') {
		return(reverse_bytes(unpack("H*", sha256(sha256(pack "H*", $_[0])))));		
	}
	elsif ($_[1] eq 'be') {
		return(unpack("H*", sha256(sha256(pack "H*", $_[0]))));			
	}
}

1;

