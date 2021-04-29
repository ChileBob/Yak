#!/usr/bin/perl
#
# yak : pool payout
#
# MIT License (ChileBob)
#
# Zcash : zs1a7qnkg8hr74ujj08jhjcdfs7s62yathqlyn5vd2e8ww96ln28m3t2jkxun5fp7hxjntcg8ccuvs
# Ycash : ys17fsj64ydl93net807xr00ujz2lnrf22cjf4430vvz69vpaat8t3hrdjmkvj7thrw4fdaz7l0pns

package payout;

my $debug = 0;															# debug verbosity for this package

#########################################################################################################################################################################
#
# CHANGING ANYTHING BELOW THIS LINE IS A REALLY BAD IDEA !! 
#
#########################################################################################################################################################################

use Data::Dumper;														# debugging

use File::Path qw(make_path);													# create spool directories

use YAML qw(LoadFile);															# write miner shares to spool directory

sub load_shares {

	my ($block) = @_;													# current block

	my @pool_transparent = ();												# array of addresses we've mined to

	my $shares = {};													# total shares

	opendir my $dir, "$main::install/spool/unpaid/";									# load array
	@pool_transparent = grep ! /^\./, readdir ($dir);
	close ($dir);

	foreach my $pool_addr (@pool_transparent) {

		opendir my $dir, "$main::install/spool/unpaid/$pool_addr/shares/";								# load shares
		my @share_block = grep ! /^\./, sort {$a <=> $b} readdir ($dir);
		close ($dir);

		foreach my $share_file (@share_block) {
			my $share = LoadFile("$main::install/spool/unpaid/$pool_addr/shares/$share_file");

			print "BLOCK $share_file\n";
			print Dumper $share,
		}
	}
}

1;	# all packages are true
