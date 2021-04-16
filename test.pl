#!/usr/bin/perl

my $teststr = "123456789012345678901234567890";

while (my $three = substr($teststr,0,3)) {
	print "$three\n";
	$teststr = substr($teststr,3);
}

