#!/usr/bin/perl
#
# yak-zec : packet generation & parsing
#
# MIT License (ChileBob)
#
# Zcash : zs1a7qnkg8hr74ujj08jhjcdfs7s62yathqlyn5vd2e8ww96ln28m3t2jkxun5fp7hxjntcg8ccuvs
# Ycash : ys17fsj64ydl93net807xr00ujz2lnrf22cjf4430vvz69vpaat8t3hrdjmkvj7thrw4fdaz7l0pns

# TODO: generate() : receives arrayref of data in source format (strings, binary, etc), add conversions & enforce sizes etc

package packet;
			
use Devel::Size qw(total_size);		# used to determine raw data size before generating packets
use Convert::Base64;			# used to encode packets for transport

use Data::Dumper;			# debugging

require './common.pm';			# common subs
require './aes256.pm';			# AES encrypt/decrypt

my $maxbytes = 16384;			# maximum packet size (websock server hard limit)

# TRANSPARENT TRANSCTION NOTIFICATION
#
# 	<type>		u8										('0x00' : type, '0x00' = mempool txn)
# 	<version>	u8										('0x01' : version)
# 	<taddr count>	uint32										(number of transparent outputs)
# 	<txid>		32-bytes									(txid)
# 	<taddr data>	<taddr_count> * (<amount 8-bytes> + <address 35-bytes>)				(transparent output data)

# SHIELDED TRANSCTION NOTIFICATION
# 	<type>		u8										('0x01' : type, '0x00' = mempool txn)
# 	<version>	u8										('0x01' : version)
# 	<zaddr count>	uint32										(number of shielded outputs)
# 	<txid>		32-bytes									(txid)
#	<zaddr data>	<zaddr_count> * <ciphertext 544-bytes>						(shielded output ciphertext : AES256)

# TRANSACTION CONFIRMATIONS
#
#	<type>		u8										('0x02' : type, txn confirmation)
#	<version>	u8										('0x01' : version)
#	<txid count>	uint32										(number of txids)
#	<txid data>	<count * 32-bytes>								(txids)

# NODE ANNOUNCEMENT
#
#	<type>		u8										('0x03' : type, node service announcement)
#	<version>	u8										('0x01' : version)
#	<fee>		uint32										(fee per block, in zats)
#	<zaddr>		<78-bytes>									(node registration zaddr)
#	<status>	u8										(node stats, 1 = up)
#	<message>	<512-bytes>									(ascii text, null padded)


my $version = 1;						# packet type version number
my $debug   = 5;						# debug verbosity

#######################################################################################################################################
#
# parse a websocket packet, returns hash of string/int vars
#
sub parse {

	my ($packet, $xfvk) = @_;				# binary packet data, bech32 encoded xfvk

	my $data;						# hash of update
	my @item;						# array of objects

	use bytes;

	if (unpack("C", substr($packet, 1, 1)) != $version) {	# version check

		common::debug($debug, "packet::parse() : Cant decode version $data->{'version'}");
		return(0);
	}

	$data->{'type'}    = unpack("C", substr($packet,0,1));	# packet type

	if ($data->{'type'} == 0) {				# TRANSPARENT TRANSACTIONS

		$data->{'txid'} = unpack("H64", substr($packet,6,32));  # get txid (32-bytes)

		for ($i = 0; $i < unpack("L", substr($packet,2,4)); $i++) { 		
			push @item, { 
				value => hex(unpack("H*", substr($packet, (($i*43)+38), 8))),	
				addr =>  unpack("A35", substr($packet, (($i*43)+46), 35))
			};
		}
		$data->{'output'} = \@item;	
		return($data);		
	}

	elsif ($data->{'type'} == 1) {				# SHEILDED TRANSACTIONS

		my @ciphertext = ();
		my @plaintext = ();

		$data->{'txid'} = unpack("H64", substr($packet,6,32));  	# get txid

		for ($i = 0; $i < unpack("L", substr($packet,2,4)); $i++) { 	# ciphertext

			my $encoded = substr($packet, (($i*544)+38), 544);	# - binary
			push @ciphertext, unpack("H*", $encoded);		# - hex string
			
										# attempt decryption
			my $decrypted = aes256::decrypt(aes256::keyGen($xfvk), $encoded);	

			if ($decrypted) {					# decryption success !!

				my $value = hex(unpack("H*", substr($decrypted, 0, 8))),	# value (zats)
				my $memo  = unpack("A*", substr($decrypted, 8));		# memo
				$memo =~ s/\0//g;						# strip null-padding

				push @plaintext, { value => $value, memo => $memo };		# store plaintext
			}
		}
		$data->{'ciphertext'} = \@ciphertext;			
		$data->{'plaintext'}  = \@plaintext;			
		return($data);				
	}

	elsif ($data->{'type'} == 2) {				# TRANSACTION CONFIRMATION

		for ($i = 0; $i < unpack("L", substr($packet,2,4)); $i++) { 
			push @item, unpack("H*", substr($packet, (($i*32)+6), 32));
		}

		$data->{'data'} = \@item;				
		return($data);					
	}

	elsif ($data->{'type'} == 3) {				# NODE ANNOUNCEMENT

		$data->{'fee'}     = unpack("L", substr($packet,2,4));		# monitoring fee (per block)
		$data->{'address'} = unpack("A78", substr($packet,6,78));	# registration address
		$data->{'status'}  = unpack("C", substr($packet,84,1));		# node status
		$data->{'message'} = unpack("A512", substr($packet,85,512));	# text from node
		$data->{'message'} =~ s/\0//g;					# remove null padding

		return($data);
	}

								# if we get this far, we failed to parse it
	common::debug($debug, "packet::parse() : Cant parse packet, type = $data->{'type'}, version = $data->{'version'}");
}


#######################################################################################################################################
#
# generate a websocket packet, type = integer, data = binary
#
sub generate {

# TODO: return arrayref of packets less than maxbytes when base64 encoded
	
	my ($type, $data, $xfvk) = @_;				# type, binary data, viewkey

	my @data_raw = @{$data};				# de-reference data, easier to handle
	my $body_records = scalar @data_raw;			# number of elements
	my $body_bytes   = total_size($data);			# data payload

	my $base64_bytes = base64_bytes($body_bytes + 2);	# base64 size

	my $packet = pack("C1", $type);				# packet header
       	$packet   .= pack("C1", $version);			# header

	if ( $type == 0) {					# TRANSACTION NOTIFICATIONS (TADDR)

		$packet .= pack("L", $body_records - 1);	# number of outputs
		$packet .= pack("H64", $data_raw[0]);		# 32-bytes, txid (hex-encoded string)

		foreach my $txn (splice(@data_raw,1)) {		# value, address
			$packet .= pack("H16", sprintf("%016X", $txn->{'value'}));	
			$packet .= pack("A35", $txn->{'address'});	
		}
	}	

	elsif ( $type == 1 ) {					# TRANSACTION NOTIFICATIONS (ZADDR)

		$packet .= pack("L", $body_records - 1);	# number of outputs
		$packet .= pack("H64", $data_raw[0]);		# 32-bytes, txid (hex-encoded string)
		$packet .= join('', splice(@data_raw, 1));	# AES ciphertext
	}	

	elsif ($type == 2) {					# TRANSACTION CONFIRMATIONS

		$packet .= pack("L", $body_records);		# number of confirmations
		$packet .= pack("H*", join('', @data_raw));	# append txids (hex-encoded strings)
	}	

	elsif ($type == 3) {					# NODE ANNOUNCEMENT 

       		$packet .= pack("C512", $data_raw[0]);		# 512-bytes, message
		$packet .= pack("L", $data_raw[1]);		# 4-bytes, zats per block
		$packet .= pack("A78", $data_raw[2]);		# registration address
		$packet .= pack("C1", $data_raw[3]);		# 1-byte, status
	}	

	common::debug(10, "packet::generate() : " . unpack("H*", $packet));	# debugging

	return(encode_base64($packet));				# return base64 encoded packet
}


#######################################################################################################################################
#
# calculate length of base64 encoded data given the raw length in bytes
#
sub base64_bytes {

	use integer;

	my $bits = $_[0] * 8;
	my $groups = $bits / 6;

	return( $groups + ($groups % 2) + ($bits % 6) );
}

1;	# all packages are true, even those that dont work properly
