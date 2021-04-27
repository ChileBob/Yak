#!/usr/bin/perl
#

use YAML qw(DumpFile);


my $hash;

$hash->{'bob'}++;
$hash->{'rosi'}++;
$hash->{'rosi'}++;


DumpFile("/tmp/test", $hash);
exit;


