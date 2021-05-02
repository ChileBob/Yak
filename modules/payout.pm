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
##########################################################################################################################################################################

use Data::Dumper;														# debugging

use File::Path qw(make_path);													# create spool directories
use YAML qw(LoadFile);														# write miner shares to spool directory


# - get lowest block number from spool that has a reward
#   - block number must be at least 100 blks lower than current height (maturity)
#   - get coinbase transaction
#     - confirm mined to pool taddr
#     - get block reward
#     - move spooled block file(s)
#
# - get all shares from spool files up to & including the reward block
#   - move share files
# 
# - calculate shares
#   - generate & spool payout transactions
#
# - send payouts
#   - check shielded balance
#   - confirm success
#   - move payout from spool


#########################################################################################################################################################################
#
# WARNING : USE SPARINGLY, THIS BREAKS MINING FOR THE FOLLOWING BLOCK
#
# newly mined coin MUST be shielded before payout
#
sub shield_coinbase {				

	my ($pool_transparent, $pool_shielded) = @_;

	print "z_shieldcoinbase $pool_transparent $pool_shielded\n";

	my $result = common::node_cli("z_shieldcoinbase $pool_transparent $pool_shielded", '', '');				# shields up to 50 utxo
	
	my $unspent = common::node_cli('z_listunspent 6 10000000', $main::pool_shielded, '' );					# get spendable confirmed balance from pool shielded address

	my $amount = 0;														
	foreach my $txn (@{$unspent}) {
		$amount += $txn->{'amount'};
	}
	return($amount);
}


#########################################################################################################################################################################
#
# load shares from spool files
#
sub load_shares {

	my ($pool_transparent, $pool_fee) = @_;											# transparent mining address, percentage pool fee

	my @blk_mature = ();													# matured blocks (100+ blocks old)
	my @blk_mined  = ();													# mined blocks

	my $pool_reward = 0;													# amount earnt by pool miners

	opendir my $dir, "$main::install/spool/unpaid/$pool_transparent/blocks/";						# load all mined blocks
	@blk_mined = grep ! /^\./, sort {$a <=> $b} readdir ($dir);
	close ($dir);

	foreach my $blk (@blk_mined) {												# filter to mature blocks
		if ( ($main::block->{'height'} - 100) > $blk) {
			push @blk_mature, $blk;
		}
	}

	my $blk_info = common::node_cli('getblock', $blk_mature[0], '');							# get block detail from node
	my $coinbase = common::node_cli('gettransaction', $blk_info->{'tx'}[0], '');						# get coinbase transaction

	foreach my $vout (@{$coinbase->{'details'}}) {										# loop through outputs
		if (($vout->{'category'} eq 'generate') && ($vout->{'address'} eq $pool_transparent)) {				# confirm its out mining address
			$pool_reward = $vout->{'amount'};									# store our reward
		}
	}

	my $pool_charge = sprintf("%.8f", $pool_reward * ($pool_fee / 100));							# deduct pool fee from payout 
	my $pool_payout = $pool_reward - $pool_charge;										# NOTE: pool fee remains in the pool shielded address

	my $shares = {};													# calculate miner shares for this block
	my $shares_total = 0;

	opendir my $dir, "$main::install/spool/unpaid/$pool_transparent/shares/";						# load logs
	my @share_block = grep ! /^\./, sort {$a <=> $b} readdir ($dir);
	close ($dir);

	foreach my $share_file (@share_block) {											# loop through logfiles

		if ($share_file <= $blk_mature[0]) {										# filter share logs, up to mined block

			my $share = LoadFile("$main::install/spool/unpaid/$pool_transparent/shares/$share_file");		# load share logfile
			
			foreach my $miner (keys %$share) {									# generate hash of shares for each miner
				if ($share->{$miner} > 0) {									# ignore zero logs
					$shares_total += $share->{$miner};
					$shares->{$miner} += $share->{$miner};
				}
			}
		}
	}

	my $zats_per_share  = $pool_payout / $shares_total;									# calculate miner payout per share

	foreach my $miner (keys %$shares) {											# change miner share count to zats earnt
		$shares->{$miner} = sprintf("%.8f", ($shares->{$miner} * $zats_per_share ));
	}				

	return($shares);													# returns hash of addresses & amount to pay
}

1;	# all packages are true
