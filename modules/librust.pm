#!/usr/bin/perl
#
# yak : FFI connections to rust libraries
#
# MIT License (ChileBob)
#
# Zcash : zs1a7qnkg8hr74ujj08jhjcdfs7s62yathqlyn5vd2e8ww96ln28m3t2jkxun5fp7hxjntcg8ccuvs
# Ycash : ys17fsj64ydl93net807xr00ujz2lnrf22cjf4430vvz69vpaat8t3hrdjmkvj7thrw4fdaz7l0pns

#########################################################################################################################################################################
#
# CHANGING ANYTHING BELOW THIS LINE IS A REALLY BAD IDEA !! 
#
#########################################################################################################################################################################

package librust;

use Data::Dumper;															# debugging

use FFI::Platypus;															# FFI interface to librustzcash
use FFI::Platypus::Buffer qw( scalar_to_buffer);											# 
use FFI::Platypus::Memory qw( malloc memcpy free);											# 

my $ffi = FFI::Platypus->new( api => 1);												# FFI

sub init {																# attach subs

	my ($library) = @_;

	$ffi->lib($library) || die ("Failed to load rust library $library"); 									# load library

	$ffi->attach( 'librustzcash_xfvk_decrypt_note'  => [ 'int', 'string', 'string', 'string', 'string', 'opaque', 'opaque' ] => 'int');	# decrypt note with xfvk 
	$ffi->attach( 'librustzcash_zip32_xfvk_address' => [ 'string', 'string', 'opaque', 'opaque'  ] => 'int');				# derive address from xfvk
	$ffi->attach( 'librustzcash_crh_ivk'            => [ 'string', 'string', 'opaque' ] => 'void');						# derive ivk from ak & nk
	$ffi->attach( 'librustzcash_xfvk_to_ivk'        => [ 'string', 'opaque' ] => 'int');							# derive ivk from xfvk
}


#########################################################################################################################################################################
#
# Derive incoming viewkey from extended full viewkey
#
sub xfvk_to_ivk {

	my ($xfvk_str) = @_;

	$xfvk_str = common::xfvk_check($xfvk_str);											# check length & prefix
	if (!$xfvk_str) {
		return(0);
	}

	my $ivk_ret = pack("c32", 0);													# allocate memory for response
	my ($ivk_ptr, $ivk_size) = scalar_to_buffer $ivk_ret;

	librustzcash_xfvk_to_ivk ($xfvk_str, $ivk_ptr);											# where the magic happens

	return(bech32::encode('zivks', $ivk_ret));											# return ivk as bech32 string
}


#######################################################################################################################################
#
# Derive payment address from extended full viewkey 
#
sub xfvk_to_addr {

	my ($xfvk_str) = @_;														# bech32 encoded extended full viewkey

	$xfvk_str = common::xfvk_check($xfvk_str);											# check length & prefix
	if (!$xfvk_str) {
		return(0);
	}
	else {

		my $xfvk = bech32::decode($xfvk_str);											# full viewkey (285 chars)

		my $j = pack("c11", 0);													# diversifier (11 bytes);

		my $j_ret = pack("c11", 0);												# RETURNED diversifier
		my ($j_ptr, $j_size) = scalar_to_buffer $j_ret;		

		my $addr_ret = pack("c43", 0);												# RETURNED address
		my ($addr_ptr, $addr_size) = scalar_to_buffer $addr_ret;

		librustzcash_zip32_xfvk_address( $xfvk, $j, $j_ptr, $addr_ptr);	# more magic

		return(bech32::encode('ys', $addr_ret));										# return as bech32 encoded string
	}
}


#######################################################################################################################################
#
# Attempt to decode a sapling transaction 
#
sub decrypt_note {

	my ($height, $xfvk, $cmu, $epk, $enc_ciphertext) = @_;										# height (int), hex-encoded strings (all other vars)

	$xfvk = common::xfvk_check($xfvk);												# check viewkey for length & prefix
	if (!$xfvk) {
		return(0);
	}

	my $value_ret = pack("c8", 0);													# allocate memory for returned values
	my ($value_ptr, $value_size) = scalar_to_buffer $value_ret;

	my $memo_ret = pack("c512", 0); 
	my ($memo_ptr, $memo_size) = scalar_to_buffer $memo_ret;	

	my $result = librustzcash_xfvk_decrypt_note(											# call the FFI function we attached earlier
		$height,														# (u32)		block height
		pack("A285", $xfvk),													# (285-bytes)	full viewkey
		pack("H64", $cmu),													# (32-bytes)	commitment u-coordinate    
		pack("H64", $epk),													# (32-bytes)	ephemeral key    
		pack("H1160", $enc_ciphertext),												# (580-bytes)	encrypted 

		$value_ptr,														# (8-bytes)	value (u64)
		$memo_ptr														# (512-bytes)	memo (null padded)
	);
	return( {status => $result, addr => $addr_ret, value => $value_ret, memo => $memo_ret} );
}

1;

