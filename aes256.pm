#!/usr/bin/perl
#
# yak-zec : AES256 encryption/decryption
#
# MIT License (ChileBob)
#
# Zcash : zs1a7qnkg8hr74ujj08jhjcdfs7s62yathqlyn5vd2e8ww96ln28m3t2jkxun5fp7hxjntcg8ccuvs
# Ycash : ys17fsj64ydl93net807xr00ujz2lnrf22cjf4430vvz69vpaat8t3hrdjmkvj7thrw4fdaz7l0pns

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

	# TODO: Authenticate ciphertext
	
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

	# TODO: Authenticate ciphertext
	
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

1;										# have to return true, we're a package

