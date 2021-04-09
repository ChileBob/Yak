#!/usr/bin/perl
#

use integer;
my $data = pack("H*", 'deadbeef');

my $bits = length($data) * 8;

my $base64_bytes = (length($data) * 8) / 6;
my $base64_padding = (length($data) * 8) % 6;

print "bits = $bits\n";
print "bytes = " . length($data) . "\n";
print "base64_bytes = $base64_bytes\n";
print "base64_padding = $base64_padding\n";

exit;

