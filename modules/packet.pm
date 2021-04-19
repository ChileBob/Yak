#!/usr/bin/perl

#
# yak-zec : packet generation & parsing
#
# MIT License (ChileBob)
#
# Zcash : zs1a7qnkg8hr74ujj08jhjcdfs7s62yathqlyn5vd2e8ww96ln28m3t2jkxun5fp7hxjntcg8ccuvs
# Ycash : ys17fsj64ydl93net807xr00ujz2lnrf22cjf4430vvz69vpaat8t3hrdjmkvj7thrw4fdaz7l0pns

package packet;
			
use Convert::Base64;											# used to encode packets for transport
use Data::Dumper;											# debugging

require "$main::install/modules/common.pm";								# common subs
require "$main::install/modules/aes256.pm";								# AES encrypt/decrypt

my $maxbytes = 4096;											# maximum packet size (websock server hard limit is 16384)

our $shielded_bytes = 576;										# ciphertext length for shielded notifications (with authentication), used to generate fakes

our $PKT_VERSION          = 0x01;									# packet version number

# NOTE : These packets are sent as plaintext to yak-yak but are subject the the rate limiter
our $PKT_ENCRYPTED        = 0x01;									# encrypted data (that we cant read)

# NOTE : These packets MUST be received as PKT_ENCRYPTED_BCAST and encrypted with a valid yak-yak key
#
our $PKT_BROADCAST        = 0xf0;									# broadcast packets
our $PKT_HEARTBEAT        = 0xf1;									# heartbeat, timed event from websocket server
our $PKT_TICKER           = 0xf2;									# price ticker update
our $PKT_ZEC_TRANSPARENT  = 0xf3;									# packet types, used outside this package
our $PKT_ZEC_SHIELDED     = 0xf4;
our $PKT_CONFIRMATION     = 0xf5;
our $PKT_YEC_TRANSPARENT  = 0xf6;								
our $PKT_YEC_SHIELDED     = 0xf7;
our $PKT_ENCRYPTED_BCAST  = 0xff;									# encrypted data for broadcast

# TRANSPARENT NOTIFICATION (PKT_ZEC_TRANSPARENT, PKT_YEC_TRANSPARENT)
#
# 	<type>		u8										(type)
# 	<version>	u8										(version)
# 	<txid>		32-bytes									(txid)
# 	<taddr count>	uint32										(number of transparent outputs)
# 	<taddr data>	<taddr_count> * (<amount 8-bytes> + <address 35-bytes>)				(transparent output data)

# SHIELDED NOTIFICATION (PKT_ZEC_SHIELDED, PKT_YEC_SHIELDED)
# 	<type>		u8										(type)
# 	<version>	u8										(version)
# 	<txid>		32-bytes									(txid)
# 	<zaddr count>	uint32										(number of shielded outputs)
#	<zaddr data>	<zaddr_count> * <ciphertext 583-bytes>						(shielded output ciphertext : AES256)

# CONFIRMATIONS (PKT_CONFIRMATION)
#
#	<type>		u8										(type)
#	<version>	u8										(version)
#	<txid count>	uint32										(number of txids)
#	<txid data>	<count * 32-bytes>								(txids)

# BROADCAST (PKT_ENCRYPTED)
#
#	<type>		u8										(type)
#	<version>	u8										(version)
#	<fee>		uint32										(fee per block, in zats)
#	<zaddr>		<78-bytes>									(node registration zaddr)
#	<status>	u8										(node stats, 1 = up)
#	<message>	<512-bytes>									(ascii text, null padded)

# ENCRYPTED BROADCAST (PKT_ENCRYPTED_BCAST)
#
#	<type>		u8										(type)
#	<version>	u8										(version)
#	<ciphertext>	<variable>									(ciphertext)

# HEARTBEAT (PKT_HEARTBEAT)
#
# 	<type>		u8										(type)
# 	<version>	u8										(version)

# TICKER (PTK_TICKER)
#
# 	<type>		u8										(type)
# 	<version>	u8										(version)
# 	<source>	<16-bytes>									(source		(string)
# 	<timestamp>	uint32										(timestamp	(epoch)
# 	<data>		<24-bytes. per record>								(3-bytes)	coin 		(ZEC/YEC)
# 													(3-bytes)	currency	(USD, GBP, EUR)
# 													(8-bytes)	price		(integer component, hex)
# 													(8-bytes)	price		(decimal decimal, hex)

my $debug   = 5;											# debug verbosity

#######################################################################################################################################
#
# parse a websocket packet, returns hash of string/int vars
#
sub parse {

	my ($packet, $keys, $transport ) = @_;								# binary packet data, bech32 encoded xfvk

	my $data;											# hash of update
	my @viewkeys = @{$keys};									# viewkeys to use
	my @item;											# array of objects

	if ($transport eq 'BASE64') {									# convert to binary
		$packet = decode_base64($packet);
	}

	use bytes;

	if (unpack("C", substr($packet, 1, 1)) != $PKT_VERSION) {					# version check

		common::debug($debug, "packet::parse() : Cant decode version $data->{'version'}");
		return(0);
	}

	$data->{'type'}    = unpack("C", substr($packet,0,1));	# packet type

	if ( $data->{'type'} == $PKT_ENCRYPTED_BCAST ) {						# encrypted data for broadcast

		$data->{'ciphertext'} = substr($packet, 2);						# strip the header

		foreach my $key (@viewkeys) {

			$data->{'plaintext'} = aes256::decrypt($key, $data->{'ciphertext'});			# attempt to decrypt

			if ($data->{'plaintext'}) {								# success !! return plaintext
				return($data);
			}
		}

		$data->{'type'} = $PKT_ENCRYPTED;							# none of our keys worked
		return($data);
	}

	elsif ( ($data->{'type'} == $PKT_ZEC_TRANSPARENT) || ($data->{'type'} == $PKT_YEC_TRANSPARENT) ) {	# TRANSPARENT TRANSACTIONS
	
		$data->{'txid'} = unpack("H64", substr($packet, 2, 32));					# txid

		$data->{'coin'} = 'ZEC';									# coin type
		if ($data->{'type'} == $PKT_YEC_TRANSPARENT) {
			$data->{'coin'} = 'YEC';
		}

		my $records = substr($packet, 34);								# extract records

		while (my $record = substr($records, 0, 43)) {
			push @item, { value => hex(unpack("H*", substr($record, 0, 8))), addr =>  unpack("A35", substr($record, 8, 35)) };
			$records = substr($records, 43);
		}
		$data->{'output'} = \@item;	
	
		return($data);		
	}

	elsif ( ($data->{'type'} == $PKT_ZEC_SHIELDED) || ($data->{'type'} == $PKT_YEC_SHIELDED) ) {	# SHIELDED TRANSACTIONS

		my @plaintext = ();

		my $records = substr($packet, 34);								# extract records

		while (my $ciphertext = substr($records, 0, $shielded_bytes)) {				# loop through output ciphertexts

			SHIELDED_KEYS: foreach my $key (@viewkeys) {									# try all our viewkeys

				my $decrypted = aes256::decrypt($key, $ciphertext);				# attempt to decrypt
	
				if ($decrypted) {								# auth included in plaintext
				
					my $value = hex(unpack("H*", substr($decrypted, 0, 8))),		# value
					my $memo = unpack("A*", substr($decrypted, 8, 512));			# memo
					$memo =~ s/\0//g;							# strip null-padding
					push @plaintext, { value => $value, memo => $memo };			# store plaintext
				}
			}
			$records = substr($records, $shielded_bytes);
		}
		
		if (scalar @plaintext > 0) {								# decryption worked, return plaintext

			$data->{'txid'} = unpack("H64", substr($packet,2,32));  					# get txid
	
			$data->{'coin'} = 'ZEC';									# coin type
			if ($data->{'type'} == $PKT_YEC_SHIELDED) {
				$data->{'coin'} = 'YEC';
			}
			$data->{'plaintext'}  = \@plaintext;			
		}
		else {											# decryption failed
			$data->{'type'} = $PKT_ENCRYPTED;
		}
		return($data);				
	}

	elsif ($data->{'type'} == $PKT_CONFIRMATION) {							# TRANSACTION CONFIRMATION (ZCASH)

		my $records = substr($packet, 2);

		while (my $record = substr($records, 0, 32)) {
			push @item, unpack("H*", $record);
			$records = substr($records, 32);
		}
		$data->{'data'} = \@item;				
		return($data);					
	}

	elsif ($data->{'type'} == $PKT_BROADCAST) {							# BROADCAST 
	
		$data->{'nodename'} = unpack("A512", substr($packet, 2, 512));				# text from node
		$data->{'nodename'} =~ s/\0//g;								# remove null padding

		$data->{'fee'}     = unpack("L", substr($packet, 514, 4));				# monitoring fee (per block)
		$data->{'address'} = unpack("A78", substr($packet,518, 78));				# registration address
		$data->{'status'}  = unpack("C", substr($packet,596, 1));				# node status

		return($data);
	}

        elsif ($data->{'type'} == $PKT_HEARTBEAT) {							# HEARTBEAT

		$data->{'tick'} = unpack("A4", substr($packet, 2, 4));

		return($data);		
	}

	elsif ($data->{'type'} == $PKT_TICKER) {							# TICKER 
	
		$data->{'source'} = unpack("A16", substr($packet, 2, 16));				# text from node
		$data->{'source'} =~ s/\0//g;								# remove null padding

		$data->{'epoch'}   = unpack("L", substr($packet, 18, 4));				# broadcast timestamp (epoch)

		my @quote = ();										# generate prices as array of hashes

		my $records = substr($packet, 22);							# remaining data are fixed length records

		while (my $record = substr($records, 0, 38)) {						# loop through records
			my $price = { 
				coin     => unpack("A3", substr($record, 0, 3)),
				currency => unpack("A3", substr($record, 3, 3)),
				quote    => hex(unpack("H*", substr($record, 6, 8))) . "." . hex(unpack("H*", substr($record, 14, 8)))
			};
			$records = substr($records, 22);
			push @quote, $price;								
		}
		$data->{'price'} = \@quote;

		return($data);
	}

	else {
													# if we get this far, we failed to parse 
		common::debug(0, "packet::parse() : Cant parse packet, type = $data->{'type'}, version = $data->{'version'}");
	}
}


#######################################################################################################################################
#
# generate a websocket packet, type = integer, data = binary
#
sub generate {

	my ($type, $data, $key) = @_;									# type, data (hash), encryption key (string)

	my @data_raw = @{$data};									# de-reference data, easier to handle

	my @packet;											# array of packets to send

	my $header = pack("C1", $type) . pack("C1", $PKT_VERSION);					# packet header

	if ( ($type == $PKT_ZEC_TRANSPARENT) || ($type == $PKT_YEC_TRANSPARENT) ) {			# TRANSPARENT TRANSACTION NOTIFICATIONS (TADDR/SADDR)

		my $data = '';

		$header .= pack("H64", $data_raw[0]);							# add txid to header 

		foreach my $txn (splice(@data_raw, 1) ) {						# value, address
			
			my $raw = pack("H*", sprintf("%016X", $txn->{'value'})) . pack("A35", $txn->{'address'});

			if (base64_bytes(length($header) + length($data) + length($raw)) < $maxbytes) {	
				$data .= $raw;
			}
			else  {										# max size, add packet to array & start another
				push @packet, encode_base64(generate_encrypted($header . $data));
				$data = $raw;								# start a new packet
			}
		}
		push @packet, encode_base64(generate_encrypted($header . $data));			# remaining data into new packet
	}	

	elsif ( ($type == $PKT_ZEC_SHIELDED ) || ($type == $PKT_YEC_SHIELDED) ) {			# SHIELDED TRANSACTION NOTIFICATIONS (ZADDR/YADDR)

		my $data = '';

		$header .= pack("H64", $data_raw[0]);							# add txid to header 

		foreach my $txn (splice(@data_raw, 1)) {						# value, address
			$data .= $txn;
		}
		push @packet, encode_base64(generate_encrypted($header . $data));			# remaining data into new packet
	}	

	elsif ($type == $PKT_CONFIRMATION) {								# TRANSACTION CONFIRMATIONS

		my $data = '';

		foreach my $txid (@data_raw) {								# txid, hex-encode string
			
			my $raw = pack("H64", $txid);

			if (base64_bytes(length($header) + length($data) + length($raw)) < $maxbytes) {	
				$data .= $raw;
			}
			else  {										# packet is max size, add to array
				push @packet, encode_base64(generate_encrypted($header . $data));
				$data = $raw;								# start a new packet
			}
		}
		push @packet, encode_base64(generate_encrypted($header . $data));			# remaining data into new packet
	}	

	elsif ($type == $PKT_BROADCAST) {								# BROADCAST 

       		$data = pack("A512", $data_raw[0]);							# 512-bytes, message
		$data .= pack("L", $data_raw[1]);							# 4-bytes, zats per block
		$data .= pack("A78", $data_raw[2]);							# registration address
		$data .= pack("C1", $data_raw[3]);							# 1-byte, status

		push @packet, encode_base64(generate_encrypted($header . $data));			# create packet
	}	

	elsif ($type == $PKT_HEARTBEAT) {								# HEARTBEAT

		push @packet, encode_base64(generate_encrypted($header));				# create packet
	}

	elsif ($type == $PKT_TICKER) {									# TICKER

		my $data = pack("A16", $data_raw[0]);							# 16-bytes, ascii string, source of prices
		$data .= pack("L", time());								# epoch time

		foreach my $quote (splice(@data_raw, 1)) {

			if ($quote) {
				$data .= pack("A6", uc(substr($quote,0,6)));				# 6-bytes, pair code (ie: ZECUSD)
	
				my @parts = split(/\./, substr($quote,6));				# split price into integer & decimal parts

				foreach my $part (@parts) {						# 8-bytes for each part, which is plenty !
					my $hexpart = sprintf("%X", $part);
					while (length($hexpart) < 16) {
						$hexpart = '0' . $hexpart;
					}
					$data .= pack("H*", $hexpart);
				}
			}
		}
		push @packet, encode_base64(generate_encrypted($header . $data));			# create packet
	}

	return(@packet);										# return of base64 encoded packets
}


#######################################################################################################################################
#
# encrypt (wrap) packet, yak-yak will only broadcast notifications it can decrypt
#
sub generate_encrypted {

	my ($plaintext) = @_;										# plaintext (binary)

	my $header = pack("C1", $PKT_ENCRYPTED_BCAST) . pack("C1", $PKT_VERSION);			# packet header

	return( $header . aes256::encrypt($main::key, $plaintext));					# encrypt using yak-yak key
}


#######################################################################################################################################
#
# calculate length of base64 encoded data from data length in bytes
#
sub base64_bytes {

	use integer;

	my $bits = $_[0] * 8;
	my $groups = $bits / 6;

	return( $groups + ($groups % 2) + ($bits % 6) );
}

1;													# all packages are true, even those that dont work properly
