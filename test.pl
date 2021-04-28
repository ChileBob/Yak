#!/usr/bin/perl

use Data::Dumper;

my $string = '000000000000000000000000000000874598754954459945945699456945969456777777777777777777777777777';


print count_zero($string) . "\n";
exit;


sub count_zero {

	my ($string) = @_;

	my $count = 0;
	foreach my $char (split(//, $string)) {
		if ($char eq '0') {
			$count++;
		}
		else {
			return($count);
		}
	}
	return($count);
}


