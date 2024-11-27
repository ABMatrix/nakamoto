// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus parameters.
//!
//! This module provides a predefined set of parameters for different Bitcoin
//! chains (such as mainnet, testnet).
//!

use crate::network::Network;
use bitcoin::util::uint::Uint256;
use crate::block::Height;

/// Lowest possible difficulty for Mainnet. See comment on Params::pow_limit for more info.
const MAX_BITS_BITCOIN: Uint256 = Uint256([
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x00000000ffff0000u64,
]);
/// Lowest possible difficulty for Testnet. See comment on Params::pow_limit for more info.
const MAX_BITS_TESTNET: Uint256 = Uint256([
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x00000000ffff0000u64,
]);
/// Lowest possible difficulty for Signet. See comment on Params::pow_limit for more info.
const MAX_BITS_SIGNET: Uint256 = Uint256([
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x00000377ae000000u64,
]);
/// Lowest possible difficulty for Regtest. See comment on Params::pow_limit for more info.
const MAX_BITS_REGTEST: Uint256 = Uint256([
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x7fffff0000000000u64,
]);

/// Lowest possible difficulty for DOGECOINMainnet.
const MAX_BITS_DOGEMAINNET: Uint256 = Uint256([
    0xffffffffffffffffu64,
    0xffffffffffffffffu64,
    0xffffffffffffffffu64,
    0x00000fffffffffffu64,
]);
/// Lowest possible difficulty for DOGECOINTestnet.
const DOGE_MAX_DOGETESTNET: Uint256 = Uint256([
    0xffffffffffffffffu64,
    0xffffffffffffffffu64,
    0xffffffffffffffffu64,
    0x00000fffffffffffu64,
]);
/// Lowest possible difficulty for DOGECOINRegtest.
const DOGE_MAX_DOGEREGTEST: Uint256 = Uint256([
    0xffffffffffffffffu64,
    0xffffffffffffffffu64,
    0xffffffffffffffffu64,
    0x7fffffffffffffffu64,
]);

/// Parameters that influence chain consensus.
#[derive(Debug, Clone)]
pub struct Params {
    /// Network for which parameters are valid.
    pub network: Network,
    /// Time when BIP16 becomes active.
    pub bip16_time: u32,
    /// Block height at which BIP34 becomes active.
    pub bip34_height: u32,
    /// Block height at which BIP65 becomes active.
    pub bip65_height: u32,
    /// Block height at which BIP66 becomes active.
    pub bip66_height: u32,
    /// Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
    /// (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
    /// Examples: 1916 for 95%, 1512 for testchains.
    pub rule_change_activation_threshold: u32,
    /// Number of blocks with the same set of rules.
    pub miner_confirmation_window: u32,
    /// Proof of work limit value. It contains the lowest possible difficulty.
    ///
    /// Note that this value differs from Bitcoin Core's powLimit field in that this value is
    /// attainable, but Bitcoin Core's is not. Specifically, because targets in Bitcoin are always
    /// rounded to the nearest float expressible in "compact form", not all targets are attainable.
    /// Still, this should not affect consensus as the only place where the non-compact form of
    /// this is used in Bitcoin Core's consensus algorithm is in comparison and there are no
    /// compact-expressible values between Bitcoin Core's and the limit expressed here.
    pub pow_limit: Uint256,
    /// Expected amount of time to mine one block.
    pub pow_target_spacing: u64,
    /// Difficulty recalculation interval.
    pub pow_target_timespan: u64,
    /// Determines whether minimal difficulty may be used for blocks or not.
    pub allow_min_difficulty_blocks: bool,
    /// Determines whether retargeting is disabled for this network or not.
    pub no_pow_retargeting: bool,
}

impl Params {
    /// Creates parameters set for the given network.
    pub fn new(network: Network) -> Self {
        match network {
            Network::Mainnet => Params {
                network: Network::Mainnet,
                bip16_time: 1333238400,                 // Apr 1 2012
                bip34_height: 227931, // 000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8
                bip65_height: 388381, // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
                bip66_height: 363725, // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
                rule_change_activation_threshold: 1916, // 95%
                miner_confirmation_window: 2016,
                pow_limit: MAX_BITS_BITCOIN,
                pow_target_spacing: 10 * 60,            // 10 minutes.
                pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks.
                allow_min_difficulty_blocks: false,
                no_pow_retargeting: false,
            },
            Network::Testnet => Params {
                network: Network::Testnet,
                bip16_time: 1333238400,                 // Apr 1 2012
                bip34_height: 21111, // 0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8
                bip65_height: 581885, // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
                bip66_height: 330776, // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
                rule_change_activation_threshold: 1512, // 75%
                miner_confirmation_window: 2016,
                pow_limit: MAX_BITS_TESTNET,
                pow_target_spacing: 10 * 60,            // 10 minutes.
                pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks.
                allow_min_difficulty_blocks: true,
                no_pow_retargeting: false,
            },
            Network::Signet => Params {
                network: Network::Signet,
                bip16_time: 1333238400, // Apr 1 2012
                bip34_height: 1,
                bip65_height: 1,
                bip66_height: 1,
                rule_change_activation_threshold: 1916, // 95%
                miner_confirmation_window: 2016,
                pow_limit: MAX_BITS_SIGNET,
                pow_target_spacing: 10 * 60,            // 10 minutes.
                pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks.
                allow_min_difficulty_blocks: false,
                no_pow_retargeting: false,
            },
            Network::Regtest => Params {
                network: Network::Regtest,
                bip16_time: 1333238400,  // Apr 1 2012
                bip34_height: 100000000, // not activated on regtest
                bip65_height: 1351,
                bip66_height: 1251,                    // used only in rpc tests
                rule_change_activation_threshold: 108, // 75%
                miner_confirmation_window: 144,
                pow_limit: MAX_BITS_REGTEST,
                pow_target_spacing: 10 * 60,            // 10 minutes.
                pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks.
                allow_min_difficulty_blocks: true,
                no_pow_retargeting: true,
            },
            Network::DOGECOINMAINNET => Params {
                network,
                bip16_time: 1333238400,
                bip34_height: 1034383,
                bip65_height: 3464751,
                bip66_height: 1034383,
                rule_change_activation_threshold: 9576,
                miner_confirmation_window: 10080,
                pow_limit: MAX_BITS_DOGEMAINNET,
                pow_target_spacing: 60,
                pow_target_timespan: 60,
                allow_min_difficulty_blocks: false,
                no_pow_retargeting: false,
            },
            Network::DOGECOINTESTNET => Params {
                network,
                bip16_time: 1333238400,
                bip34_height: 708658,
                bip65_height: 1854705,
                bip66_height: 708658,
                rule_change_activation_threshold: 2880,
                miner_confirmation_window: 10080,
                pow_limit: DOGE_MAX_DOGETESTNET,
                pow_target_spacing: 60,
                pow_target_timespan: 60,
                allow_min_difficulty_blocks: true,
                no_pow_retargeting: false,
            },
            Network::DOGECOINREGTEST => Params {
                network,
                bip16_time: 1333238400,
                bip34_height: 100000000,
                bip65_height: 1351,
                bip66_height: 1251,
                rule_change_activation_threshold: 540,
                miner_confirmation_window: 720,
                pow_limit: DOGE_MAX_DOGEREGTEST,
                pow_target_spacing: 1,
                pow_target_timespan: 1,
                allow_min_difficulty_blocks: true,
                no_pow_retargeting: true,
            },
        }
    }

    /// Calculates the number of blocks between difficulty adjustments.
    pub fn difficulty_adjustment_interval(&self) -> u64 {
        self.pow_target_timespan / self.pow_target_spacing
    }

    /// Doge digishield_difficulty_calculation
    pub fn doge_digishield_difficulty_calculation(&self, height: Height) -> bool {
        match self.network {
            Network::DOGECOINMAINNET | Network::DOGECOINTESTNET=> {
                height > 144999
            }
            Network::DOGECOINREGTEST => {
                height > 10
            }
            _ => unreachable!()
        }
    }

    /// Doge strict_chain_id
    pub fn doge_strict_chain_id(&self) -> bool {
        match self.network {
            Network::DOGECOINMAINNET | Network::DOGECOINREGTEST=> {
                true
            }
            Network::DOGECOINTESTNET => {
                false
            }
            _ => unreachable!()
        }
    }

    /// Doge allow_min_difficulty_blocks
    pub fn doge_allow_min_difficulty_blocks(&self, height: Height) -> bool {
        match self.network {
            Network::DOGECOINMAINNET => {
                false
            }
            Network::DOGECOINTESTNET => {
                if height <= 144999 {
                    true
                }else {
                    height > 157499
                }
            }
            Network::DOGECOINREGTEST => {
                true
            }
            _ => unreachable!()
        }
    }

    /// Doge pow_target_timespan
    pub fn doge_pow_target_timespan(&self, height: Height) -> u64{
        match self.network {
            Network::DOGECOINMAINNET | Network::DOGECOINTESTNET=> {
                if height <= 144999 {
                    4 * 60 * 60
                }else {
                    60
                }
            }
            Network::DOGECOINREGTEST => {
                if height <= 9 {
                    4 * 60 * 60
                }else {
                    1
                }
            }
            _ => unreachable!()
        }
    }
}

#[cfg(test)]
mod test_doge_params {
    use crate::network::Network;
    use crate::params::Params;

    #[test]
    fn test_hardfork_parameters() {
        // mainnet
        let params = Params::new(Network::DOGECOINMAINNET);
        assert_eq!(params.doge_pow_target_timespan(0), 14400);
        assert_eq!(params.doge_digishield_difficulty_calculation(0), false);

        assert_eq!(params.doge_pow_target_timespan(144999), 14400);
        assert_eq!(params.doge_digishield_difficulty_calculation(144999), false);

        assert_eq!(params.doge_pow_target_timespan(145000), 60);
        assert_eq!(params.doge_digishield_difficulty_calculation(145000), true);

        assert_eq!(params.doge_pow_target_timespan(371336), 60);
        assert_eq!(params.doge_digishield_difficulty_calculation(371336), true);

        assert_eq!(params.doge_pow_target_timespan(371337), 60);
        assert_eq!(params.doge_digishield_difficulty_calculation(371337), true);

        // testnet
        let params = Params::new(Network::DOGECOINMAINNET);
        assert_eq!(params.doge_pow_target_timespan(0), 14400);
        assert_eq!(params.doge_digishield_difficulty_calculation(0), false);

        assert_eq!(params.doge_pow_target_timespan(144999), 14400);
        assert_eq!(params.doge_digishield_difficulty_calculation(144999), false);

        assert_eq!(params.doge_pow_target_timespan(145000), 60);
        assert_eq!(params.doge_digishield_difficulty_calculation(145000), true);

        assert_eq!(params.doge_pow_target_timespan(371336), 60);
        assert_eq!(params.doge_digishield_difficulty_calculation(371336), true);

        assert_eq!(params.doge_pow_target_timespan(371337), 60);
        assert_eq!(params.doge_digishield_difficulty_calculation(371337), true);
    }
}