#!/usr/bin/perl


package equihash;

require "./blake2b.pm";

use warnings;
use strict;
use blake2b;

# Source : https://git.hush.is/hush/hushwebminer/src/branch/master/pool-emu/equihash.pm

sub verify {

	my ($block) = @_;

	length $block == 1487 or die "bad block length ${\length $block}";

	my ($hdr, $solsize, $sol) = unpack 'a140 a3 a1344', $block;

	$solsize eq "\xfd\x40\x05" or die "bad solution size ${\unpack 'H*', $solsize}";

	my @sol = map { oct "0b$_" } unpack '(a21)*', unpack 'B*', $sol;
	@sol == 512 or die;

	# indexes are unique
	my %uniq; @uniq{@sol} = (); keys %uniq == 512 or die "indexes are not unique";

	# indexes are ordered
	for my $step (1..9) {
		my $off = 2**($step-1);
		$sol[$_] < $sol[$_+$off] or die "no order step $step idx $_"
		for map $_*$off*2, 0 .. 2**(9-$step)-1;
	}

	# calculate hashes
	my $blake = blake2b::new (
		hashlen  => 50,
		personal => ('ZcashPoW' . pack 'VV', 200, 9),
	)->update ($hdr);

	@sol = map {
		my $bl = $blake->copy ()->final (pack 'V', $_ / 2);
		length $bl == 50 or die;
		substr $bl, $_ % 2 * 25, 25
	} @sol;

	# hashes xored give zeroes
	for my $step (1..9) {
		@sol = map $sol[$_*2] ^ $sol[$_*2+1], 0 .. @sol/2 - 1;
		unpack ('B' . $step * 20, $_) =~ /^0+\z/
		@sol == 1 or die;

		# final xor is all zeroes
		$sol[0] =~ /^\x00{25}\z/ or die "bad final";
	}
}

1;

