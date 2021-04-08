#!/usr/bin/perl
#
# yak-zec : packet parsing
#
# MIT License (ChileBob)
#
# Zcash : zs1a7qnkg8hr74ujj08jhjcdfs7s62yathqlyn5vd2e8ww96ln28m3t2jkxun5fp7hxjntcg8ccuvs
# Ycash : ys17fsj64ydl93net807xr00ujz2lnrf22cjf4430vvz69vpaat8t3hrdjmkvj7thrw4fdaz7l0pns

package packet;

use Data::Dumper;

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


my $version = 1;						# packet type version number
my $debug   = 5;						# debug verbosity

#######################################################################################################################################
#
# parse a websocket packet, returns hash of string/int vars
#
sub parse {

	my ($packet) = @_;					# binary packet data

	my $data;						# hash of update
	my @item;						# array of objects

	use bytes;

	$data->{'type'}    = unpack("C", substr($packet,0,1));
	$data->{'version'} = unpack("C", substr($packet,1,1));

	if ($data->{'version'} != $version) {
		debug(5, "packet::parse() : Cant decode version $data->{'version'}");
		return(0);
	}

	if ($data->{'type'} == 0) {				# TRANSPARENT TRANSACTIONS

		$data->{'txid'} = unpack("H64", substr($packet,6,32));  # get txid (32-bytes)

		for ($i = 0; $i < unpack("L", substr($packet,2,4)); $i++) { 		
			push @item, { 
				value => hex(reverse unpack("H*", substr($packet, (($i*43)+38), 8))),	
				addr =>  unpack("A35",    substr($packet, (($i*43)+46), 35))
			};
		}
		$data->{'output'} = \@item;	
		return($data);		
	}

	elsif ($data->{'type'} == 1) {				# SHEILDED TRANSACTIONS

		$data->{'txid'} = unpack("H64", substr($packet,6,32));  # get txid (32-bytes)

		for ($i = 0; $i < unpack("L", substr($packet,2,4)); $i++) { 		# ciphertext	
			push @item, { ciphertext => substr($packet, (($i*544)+38), 544) };
		}

		$data->{'output'} = \@item;			
		return($data);				
	}

	elsif ($data->{'type'} == 2) {				# TRANSACTION CONFIRMATION

		for ($i = 0; $i < unpack("L", substr($packet,2,4)); $i++) { 
			push @item, unpack("H*", substr($packet, (($i*32)+6), 32));
		}

		$data->{'data'} = \@item;				
		return($data);					
	}
								# if we get this far, we failed to parse it
	debug(5, "packet::parse() : Cant parse packet, type = $data->{'type'}, version = $data->{'version'}");
}


#######################################################################################################################################
#
# generate a websocket packet, type = integer, data = binary
#
sub generate {

	my ($type, $data) = @_;					# type, version, arrayref to binary data

	my $packet = pack("C1", $type) . pack("C1", $version);	# header

	my $count = @{$data}; 					# count of data items
	if ($type < 2) {					# transaction notifications have txid as first data item (32-bytes)
		$count--;
	}
	$packet .= pack("L", $count);	 			# append item counter

	foreach my $element (@{$data}) {			# append data 
		$packet .= $element;
	}
	return($packet);					# assembled packet
}


#######################################################################################################################################
#
# debug
#
sub debug {

	my ($level, $message) = @_;

	if ($level <= $debug) {
		print("$message\n");
	}
}

1;	# all packages are true
