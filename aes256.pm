#!/usr/bin/perl
#
# yak-zec : AES256 encryption/decryption
#
# MIT License (ChileBob)
#
# Zcash : zs1a7qnkg8hr74ujj08jhjcdfs7s62yathqlyn5vd2e8ww96ln28m3t2jkxun5fp7hxjntcg8ccuvs
# Ycash : ys17fsj64ydl93net807xr00ujz2lnrf22cjf4430vvz69vpaat8t3hrdjmkvj7thrw4fdaz7l0pns

# TODO: Ciphertext is NOT authenticated, it should be !
# - authentication key should be sha(zaddr) derived from xfvk, only the node & client know

package aes256;

use Crypt::CBC;						# encryption mode
use Crypt::Cipher::AES;					# AES256 encryption algo
use Digest::SHA qw(sha256);				# sha hashing strings to create keys

#######################################################################################################################################
#
# generate key from a string, input can be a raw ascii string OR hex chars, output is 32-byte binary
#
sub keyGen {

	if ($_[0] =~ m/[^0-9a-fA-F]/) {					# hash char byte values
		return(sha256(pack("A*", $_[0])));
	}
	else {								# hash byte values
		return(sha256(pack("H*", $_[0])));
	}
}


#######################################################################################################################################
#
# decrypt message
#
sub decrypt {

	my ($key, $input) = @_;

	my $inputHEX = unpack("H*", $input);					# convert binary scalar input to hex-encoded string

	$ivHEX  = substr($inputHEX, 0, 32);					# init vector is first 16 bytes, 32 hex chars

	if (length($inputHEX) >= 64) {						# make sure we have more than minimum data, avoids dying horribly

		$cipherHEX = substr($inputHEX, 32, (length($inputHEX) - 32));	# ciphertext, as hex string

		my $cipher = Crypt::CBC->new({ 					# setup encyption
			'key' => $key,
			'cipher' => 'OpenSSL::AES',
			'header' => 'none',
			'iv' => pack("H*", $ivHEX),
			'literal_key' => 1,					
			'padding' => 'standard'
		});

		return($cipher->decrypt(pack("H*", $cipherHEX)));		# result is a binary scalar
	}
}


#######################################################################################################################################
#
# encrypt message								returns binary ciphertext, enrypts binary plaintext
#
sub encrypt {

	my ($key, $plaintext) = @_;						# key is a binary scalar, plaintext is a string

	$iv  = pack("H*", keyRandom(32));					# generate random init vector (32 hex chars, packs to 128-bit)

	my $cipher = Crypt::CBC->new({ 						# setup encyption
		'key' => $key,
		'cipher' => 'OpenSSL::AES',
		'header' => 'none',
		'iv' => $iv,
		'literal_key' => 1,				
		'padding' => 'standard'
	});
	my $ciphertext = $cipher->encrypt($plaintext);	

	return($iv . $ciphertext);						# return binary scalar
}


#######################################################################################################################################
#
# generate random string to use as a key (64 hex chars only, 32 bytes, 256-bits) 
#
sub keyRandom {	

	my ($key_length, $key_type) = @_;

	my @chars = ('a'..'z', 'A'..'Z', '0'..'9');
	if ($key_type eq "") {						# alpha string if any key type arg is given
		@chars = ('a'..'f', '0'..'9');				# default key type : lower case hex string
	}

	if ($key_length eq "") {					# default key length is 64 chars, which is 32 bytes
		$key_length = 64;
	}

	my $key_random = '';					
	$key_random .= $chars[rand @chars] for 1..$key_length;		# add random chars 

	return($key_random);
}

1;

