#!/usr/bin/perl
#
# yak-zec : common subs
#
# MIT License (ChileBob)
#
# Zcash : zs1a7qnkg8hr74ujj08jhjcdfs7s62yathqlyn5vd2e8ww96ln28m3t2jkxun5fp7hxjntcg8ccuvs
# Ycash : ys17fsj64ydl93net807xr00ujz2lnrf22cjf4430vvz69vpaat8t3hrdjmkvj7thrw4fdaz7l0pns

package common;

#########################################################################################################################################################################
#
# debugging output
#
sub debug {

# TODO : Send to logfile ? Maybe not (privacy!)
	my ($level, $message) = @_;
	
	if ($level <= $config->{'debug'}) { 
		print "$message\n";
	}
}

1;	# all packages are true, especially the ones that are not

