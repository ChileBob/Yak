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

1;

