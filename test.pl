#!/usr/bin/perl


use LWP::UserAgent;					# used to POST transaction alerts to URI
#use URI::Escape::XS;					# URI encodes text, even weird utf8 stuff

my $data = {
	value => 100,
	memo => "This is a multiline\nmemo with spaces.",
	txid => "lqweljkfehwhldglhdslfkhsdlhkfsd"
};

my $url = 'http://ptsv2.com/t/chilebob/post';		# URL for posting data
my $browser = LWP::UserAgent->new;

my $response = $browser->post( $url, [ value => $data->{'value'}, memo => $data->{'memo'}, txid => $data->{'txid'} ] );

print Dumper $response;

