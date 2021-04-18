#!/usr/bin/perl
#

use Data::Dumper;

my $hash = {
	'wibble' => { first => 'one', second => 'two', third => 'three' },
	'wobble' => { first => 1, second => 2, third => 3 },
};


print Dumper $hash;

foreach my $key (keys %$hash) {
	print "$hash->{$key}->{'first'}\n";
}

exit;

