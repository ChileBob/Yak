#!/usr/bin/perl
#
# yak-zec : common subs
#
# MIT License (ChileBob)
#
# Zcash : zs1a7qnkg8hr74ujj08jhjcdfs7s62yathqlyn5vd2e8ww96ln28m3t2jkxun5fp7hxjntcg8ccuvs
# Ycash : ys17fsj64ydl93net807xr00ujz2lnrf22cjf4430vvz69vpaat8t3hrdjmkvj7thrw4fdaz7l0pns

package common;

use Data::Dumper;
use LWP::UserAgent;					# used to POST transaction alerts to URI
use String::HexConvert ':all';				# convert memo hex-encoded strings

my $debug = 5;						# global debug verbosity, 0 = quiet

#########################################################################################################################################################################
#
# debugging output
#
sub debug {

# TODO: Include sub name in debug messages
	
	my ($level, $message) = @_;
	
	if ($level < $debug) { 
		print "$message\n";
	}
}

#########################################################################################################################################################################
#
# split URI into seperate components
#
sub uri_split {

	my ($uri) = @_;

	$uri =~ s/\///g;				# remove '/'
	my @parts = split(":",$uri);

	return(@parts);
}


#########################################################################################################################################################################
#
# parse command line args & return modified config hash
#
sub parse_argv {

	my ($config, $argv) = @_;

	my @argv = @{$argv};				# dereference array of args

	my @viewkeys;

	while (my $arg = shift @argv) {			# loop through args

							# key from by pattern matching value
		if ($arg =~ m/^ws/) {			# websocket server 
			$config->{'web'} = $arg;
		}
		elsif ($arg =~ m/^zmq/) {		# ZMQ connection
			$config->{'zmq'} = $arg;
		}
		elsif ($arg =~ m/^uri/) {		# URI to post events
			$config->{'uri'} = $arg;
		}
		elsif ($arg =~ m/^zxview/) {		# viewkey
			push @viewkeys, $arg;
		}
							# key followed by value
		for my $keyword ('ident', 'auth', 'xfvk', 'ivk') {
			if ($arg eq $keyword) {	
				$config->{$keyword} = shift @argv;
			}
		}

		$config->{'newkeys'} = \@viewkeys;	# arrayref of viewkeys to add

	}
	return($config);				# return config hash
};



#########################################################################################################################################################################
#
# POST data to a URI for website integration. You can test this by visiting https://ptsv2.com and setting up a URI to post data to.
#
sub website_post {

	my ($uri, $data) = @_;

	if ($uri) {					# skip if URI is not set

		my $browser = LWP::UserAgent->new;

		return( $browser->post( $uri, [ $data ] ) );
	}
}

#########################################################################################################################################################################
#
# Check to see if a packet type is listed for delivery
#
sub notify_check {

	my ($packet_type, $notifications) = @_;

	if ( grep /$packet_type/, @{$notifications} ) {
		return(1);
	}
}


#######################################################################################################################################
#
# Check Extended Full Viewing Key
#
sub xfvk_check {

    my ($xfvk_str) = @_;								# bech32 encoded extended full viewkey

    $xfvk_str =~ s/\0//g;								# strip null padding
    $xfvk_str =~ s/\s//g;								# strip whitespace

    if (index($xfvk_str, 'zxviews1') != 0) {
        common::debug(5, "xfvk_to_addr() : full viewkey had the wrong prefix, expected \'zxviews\', received \'$xfvk_str\'");
        return(0);
    }
    elsif (length($xfvk_str) < 285) {            
        common::debug(5, "xfvk_to_addr() : full viewkey too short, expected 285 chars, received " . length($xfvk_str) . " bytes" . "\n");
        return(0);
    }

    $xfvk_str = substr($xfvk_str,0,285);						# chop key to correct length
    return($xfvk_str);									# viewing key is valid
}


#######################################################################################################################################
#
# Search memo text for Extended Full Viewing Key
#
sub memo_to_xfvk {

	my ($memo) = @_;

	my @line = split("\n", hex_to_ascii($memo));					# convert memo to ascii, split into lines

	foreach $line (@line) {								# we don't control the format so check each line
		$line =~ s/\0//g;							# strip nulls

		if (my $xfvk = xfvk_check($line)) {					# check for valid extended full viewing key
			return($xfvk);
		}
	}
}
