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

my $maxbytes = 2048;			# maximum packet size (websock server hard limit)

our $PKT_TRANSPARENT  = 0x01;
our $PKT_SHIELDED     = 0x02;
our $PKT_CONFIRMATION = 0x03;
our $PKT_ANNOUNCE     = 0x04;

our $PKT_VERSION      = 0x01;

# TRANSPARENT TRANSCTION NOTIFICATION
#
# 	<type>		u8										('0x01' : type, '0x00' = mempool txn)
# 	<version>	u8										('0x01' : version)
# 	<txid>		32-bytes									(txid)
# 	<taddr count>	uint32										(number of transparent outputs)
# 	<taddr data>	<taddr_count> * (<amount 8-bytes> + <address 35-bytes>)				(transparent output data)

# SHIELDED TRANSCTION NOTIFICATION
# 	<type>		u8										('0x02' : type, '0x00' = mempool txn)
# 	<version>	u8										('0x01' : version)
# 	<txid>		32-bytes									(txid)
# 	<zaddr count>	uint32										(number of shielded outputs)
#	<zaddr data>	<zaddr_count> * <ciphertext 544-bytes>						(shielded output ciphertext : AES256)

# TRANSACTION CONFIRMATIONS
#
#	<type>		u8										('0x03' : type, txn confirmation)
#	<version>	u8										('0x01' : version)
#	<txid count>	uint32										(number of txids)
#	<txid data>	<count * 32-bytes>								(txids)

# NODE ANNOUNCEMENT
#
#	<type>		u8										('0x04' : type, node service announcement)
#	<version>	u8										('0x01' : version)
#	<fee>		uint32										(fee per block, in zats)
#	<zaddr>		<78-bytes>									(node registration zaddr)
#	<status>	u8										(node stats, 1 = up)
#	<message>	<512-bytes>									(ascii text, null padded)


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

	if (unpack("C", substr($packet, 1, 1)) != $PKT_VERSION) {	# version check

		common::debug($debug, "packet::parse() : Cant decode version $data->{'version'}");
		return(0);
	}

	$data->{'type'}    = unpack("C", substr($packet,0,1));	# packet type

	# TESTED : THIS WORKS :-)
	
	if ($data->{'type'} == $PKT_TRANSPARENT) {				# TRANSPARENT TRANSACTIONS
	
		my $count = unpack("L", substr($packet,34,4));
	
		for ($i = 0; $i < $count; $i++) { 		
			push @item, { 
				value => hex(unpack("H*", substr($packet, (($i*43)+38), 8))),	
				addr =>  unpack("A35", substr($packet, (($i*43)+46), 35))
			};
		}
		$data->{'output'} = \@item;	
	
		return($data);		
	}

	elsif ($data->{'type'} == $PKT_SHIELDED) {				# SHIELDED TRANSACTIONS

		my @ciphertext = ();
		my @plaintext = ();

		$data->{'txid'} = unpack("H64", substr($packet,2,32));  	# get txid

		for ($i = 0; $i < unpack("L", substr($packet,34,4)); $i++) { 	# ciphertext

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
		if (scalar @plaintext > 0) {
			$data->{'plaintext'}  = \@plaintext;			
		}
		$data->{'ciphertext'} = \@ciphertext;			

		return($data);				
	}

	elsif ($data->{'type'} == $PKT_CONFIRMATION) {				# TRANSACTION CONFIRMATION
	
		for ($i = 0; $i < unpack("L", substr($packet, 2, 4)); $i++) { 
			push @item, unpack("H*", substr($packet, (($i*32)+6), 32));
		}
	
		$data->{'data'} = \@item;				
		return($data);					
	}

	elsif ($data->{'type'} == $PKT_ANNOUNCE) {				# NODE ANNOUNCEMENT
	
		$data->{'fee'}     = unpack("L", substr($packet,2,4));		# monitoring fee (per block)
		$data->{'address'} = unpack("A78", substr($packet,6,78));	# registration address
		$data->{'status'}  = unpack("C", substr($packet,84,1));		# node status
		$data->{'message'} = unpack("A512", substr($packet,85,512));	# text from node
		$data->{'message'} =~ s/\0//g;					# remove null padding

		return($data);
	}
        elsif ($data->{'type'} = 0x05) {				# HEARTBEAT
		common::debug(5, "packet::parse() : heartbeart");
		$data->{'tick'} = unpack("A4", substr($packet, 2, 4));

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

	my @packet;						# array of packets to send

	my $header = pack("C1", $type) . pack("C1", $PKT_VERSION);	# packet header

	if ( $type == $PKT_TRANSPARENT) {					# TRANSACTION NOTIFICATIONS (TADDR)

		my $data = '';
		my $count = 0;

		$header .= pack("H64", $data_raw[0]);		# add txid to header 

		foreach my $txn (splice(@data_raw, 1) ) {	# value, address
			
			my $raw = pack("H*", sprintf("%016X", $txn->{'value'})) . pack("A35", $txn->{'address'});

			if (base64_bytes(length($header) + 4 + length($data) + length($raw)) < $maxbytes) {	
				$count++;
				$data .= $raw;
			}
			else  {					# max size, add packet to array & start another
				push @packet, encode_base64($header . pack("L", $count) . $data);

				$data = $raw;			# start a new packet
				$count = 1;
			}
		}
		push @packet, encode_base64($header . pack("L", $count) . $data);		# remaining data into new packet
	}	

	elsif ( $type == $PKT_SHIELDED ) {			# TRANSACTION NOTIFICATIONS (ZADDR)

		my $data = '';
		my $count = 0;

		$header .= pack("H64", $data_raw[0]);		# add txid to header 

		foreach my $txn (splice(@data_raw, 1)) {	# value, address
			
			if (base64_bytes(length($header) + 4 + length($data) + length($txn)) < $maxbytes) {	
				$count++;
				$data .= $txn;
			}
			else  {					# max size, add packet to array & start another
				push @packet, encode_base64($header . pack("L", $count) . $data);

				$data = $txn;			# start a new packet
				$count = 1;
			}
		}
		push @packet, encode_base64($header . pack("L", $count) . $data);		# remaining data into new packet
	}	

	elsif ($type == $PKT_CONFIRMATION) {					# TRANSACTION CONFIRMATIONS

		my $data = '';
		my $count = 0;

		foreach my $txid (@data_raw) {			# txid, hex-encode string
			
			my $raw = pack("H64", $txid);

			if (base64_bytes(length($header) + length($data) + length($raw)) < $maxbytes) {	
				$count++;
				$data .= $raw;
			}
			else  {					# packet is max size, add to array
				push @packet, encode_base64($header . $data);

				$data = $raw;			# start a new packet
				$count = 1;
			}
		}
		push @packet, encode_base64($header . $data);	# remaining data into new packet
	}	


	elsif ($type == $PKT_ANNOUNCE) {					# NODE ANNOUNCEMENT 

       		$data = pack("C512", $data_raw[0]);		# 512-bytes, message
		$data .= pack("L", $data_raw[1]);		# 4-bytes, zats per block
		$data .= pack("A78", $data_raw[2]);		# registration address
		$data .= pack("C1", $data_raw[3]);		# 1-byte, status

		push @packet, encode_base64($header . $data);	# create packet
	}	

	elsif ($type == 0x05) {					# HEARTBEAT

		push @packet, encode_base64($header);		# create packet
	}

	return(@packet);					# return of base64 encoded packets
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
