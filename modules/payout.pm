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

	my @blk_reward = ();													# reward blocks 

	my $total_reward = 0;

	print "Current Block : $main::block->{'height'}\n";									# current block height
	
	opendir my $dir, "$main::install/spool/unpaid/$pool_transparent/blocks/";						# get lowest mined block
	my @blk_mined = grep ! /^\./, sort {$a <=> $b} readdir ($dir);
	close ($dir);

	foreach my $blk (@blk_mined) {												# get blocks that have matured
		if ( ($main::block->{'height'} - 100) > $blk) {
			push @blk_reward, $blk;
		}
	}

	my $blk_info = common::node_cli('getblock', $blk_reward[0], '');							# oldest block first

	my $coinbase = common::node_cli('gettransaction', $blk_info->{'tx'}[0], '');						# get coinbase transaction

	foreach my $vout (@{$coinbase->{'details'}}) {
		if (($vout->{'category'} eq 'generate') && ($vout->{'address'} eq $pool_transparent)) {				# get output for pool transparent address
			$total_reward += $vout->{'amount'};									# add to payout total
		}
	}

	print "Block    : $blk_reward[0]\n";
	print "Reward   : $total_reward\n";
	print "Pool Fee : " . sprintf("%.8f", $total_reward * ($pool_fee / 100)) . "\n";

	opendir my $dir, "$main::install/spool/unpaid/$pool_transparent/shares/";						# load shares
	my @share_block = grep ! /^\./, sort {$a <=> $b} readdir ($dir);
	close ($dir);

	my $shares = {};
	my $shares_total = 0;

	foreach my $share_file (@share_block) {

		if ($share_file <= $blk_reward[0]) {

			my $share = LoadFile("$main::install/spool/unpaid/$pool_transparent/shares/$share_file");
			
			foreach my $miner (keys %$share) {
				$shares_total += $share->{$miner};
				$shares->{$miner} += $share->{$miner};
			}
		}
	}

	print "Total Shares : $shares_total\n";

	print Dumper $shares;

}

1;	# all packages are true
