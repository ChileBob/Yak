#!/usr/bin/perl
#
# tweaked version of https://github.com/brtastic/perl-bitcoin-crypto/blob/master/lib/Bitcoin/Crypto/Bech32.pm
#
# MIT License (ChileBob)
#
# Zcash : zs1a7qnkg8hr74ujj08jhjcdfs7s62yathqlyn5vd2e8ww96ln28m3t2jkxun5fp7hxjntcg8ccuvs
# Ycash : ys17fsj64ydl93net807xr00ujz2lnrf22cjf4430vvz69vpaat8t3hrdjmkvj7thrw4fdaz7l0pns
#
# - removed Bitcoin stuff as this is for zcash/ycash
# 	- no segwit
# 	- different address length

package bech32;

my @alphabet = qw( q p z r y 9 x 8 g f 2 t v d w 0 s 3 j n 5 4 k h c e 6 m u a 7 l);	# bech 32 alphabet

my $CHECKSUM_SIZE = 6;

my %alphabet_mapped = map { $alphabet[$_] => $_ } 0 .. $#alphabet;

#######################################################################################################################################
#
# generate polymod
#
sub polymod
{
	my ($values) = @_;
	my @consts = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3);
	my $chk = 1;
	for my $val (@$values) {
		my $b = ($chk >> 25);
		$chk = ($chk & 0x1ffffff) << 5 ^ $val;
		for (0 .. 4) {
			$chk ^= ((($b >> $_) & 1) ? $consts[$_] : 0);
		}
	}
	return $chk;
}

#######################################################################################################################################
#
# expand human readable part
#
sub hrp_expand
{
	my @hrp = split "", shift;
	my (@part1, @part2);
	for (@hrp) {
		my $val = ord;
		push @part1, $val >> 5;
		push @part2, $val & 31;
	}
	return [@part1, 0, @part2];
}

#######################################################################################################################################
#
# convert to char value
#
sub to_numarr
{
	my ($string) = @_;

	return [map { $alphabet_mapped{$_} } split "", $string];
}

#######################################################################################################################################
#
# generate checksum
#
sub create_checksum
{
	my ($hrp, $data) = @_;

	my $polymod = polymod([@{hrp_expand $hrp}, @{to_numarr $data}, (0) x $CHECKSUM_SIZE]) ^ 1;
	my $checksum;
	for (0 .. $CHECKSUM_SIZE - 1) {
		$checksum .= $alphabet[($polymod >> 5 * (5 - $_)) & 31];
	}
	return $checksum;
}

#######################################################################################################################################
#
# verify checksum
#
sub verify_checksum
{
	my ($hrp, $data) = @_;

	return polymod([@{hrp_expand $hrp}, @{to_numarr $data}]) == 1;
}

#######################################################################################################################################
#
# encode data as base32
#
sub encode_base32
{
	my ($bytes) = @_;

	my @data = unpack "(a5)*", unpack "B*", $bytes;
	my $result = "";
	for my $bitstr (@data) {
		my $pad = 5 - length $bitstr;
		my $num = unpack "C", pack "B*", "000$bitstr" . 0 x $pad;
		$result .= $alphabet[$num];
	}

	return $result;
}

#######################################################################################################################################
#
# decode base32 data
#
sub decode_base32
{
	my ($encoded) = @_;

	return ""
		unless length $encoded;
	my @enc_values = map { $alphabet_mapped{$_} } split "", $encoded;
	my $bits = unpack "B*", pack "C*", @enc_values;
	$bits = join "", map { substr $_, 3 } unpack "(a8)*", $bits;

	my $length_padded = length $bits;
	my $padding = $length_padded % 8;
	$bits =~ s/0{$padding}$//;

	my @data = unpack "(a8)*", $bits;
	my $result = "";
	for my $bitstr (@data) {
		$result .= pack "B8", $bitstr;
	}
	return $result;
}

#######################################################################################################################################
#
# encode data as bech32
#
sub encode
{
	my ($hrp, $bytes) = @_;
	#verify_bytestring($bytes);

	my $result = encode_base32($bytes);
	my $checksum = create_checksum($hrp, $result);

	return $hrp . 1 . $result . $checksum;
}

#######################################################################################################################################
#
# split bech32 data into human readable part, data & checksum
#
sub split_bech32
{
	my ($bech32enc) = @_;			# bech32 encoded string

	$bech32enc = lc $bech32enc;		# force to lower case

	my @parts;

	$parts[0] = $bech32enc;			# hrp
	$parts[0] =~ s/1.*//;

	$parts[1] = $bech32enc;			# data
	$parts[1] =~ s/^[^1]*1//;
	$parts[1] = substr($parts[1], 0, -6);

	$parts[2] = substr($bech32enc, -6);	# checksum

	return \@parts;
}

#######################################################################################################################################
#
# decode bech32 string
#
sub decode
{
	my ($bech32enc) = @_;

	my @parts = @{split_bech32($bech32enc)};

	return decode_base32($parts[1]);
}

1;

