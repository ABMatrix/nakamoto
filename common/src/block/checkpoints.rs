//! Checkpoints used to validate blocks at certain heights.

#[rustfmt::skip]
/// Mainnet checkpoints.
pub const MAINNET: &[(u64, &str)] = &[
    (11111,  "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"),
    (33333,  "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"),
    (74000,  "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"),
    (105000, "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"),
    (134444, "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"),
    (168000, "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"),
    (193000, "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"),
    (210000, "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"),
    (216116, "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e"),
    (225430, "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932"),
    (250000, "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"),
    (279000, "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40"),
    (295000, "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983"),
];

/// Testnet checkpoints.
#[rustfmt::skip]
pub const TESTNET: &[(u64, &str)] = &[
    (546, "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70"),
];

/// Regtest checkpoints.
pub const REGTEST: &[(u64, &str)] = &[];

/// Signet checkpoints.
pub const SIGNET: &[(u64, &str)] = &[];

#[rustfmt::skip]
/// DogecoinMainnet checkpoints.
pub const DOGECOINMAINNET: &[(u64, &str)] = &[
    (0, "1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691"),
    (104679, "35eb87ae90d44b98898fec8c39577b76cb1eb08e1261cfc10706c8ce9a1d01cf"),
    (145000, "cc47cae70d7c5c92828d3214a266331dde59087d4a39071fa76ddfff9b7bde72"),
    (371337, "60323982f9c5ff1b5a954eac9dc1269352835f47c2c5222691d80f0d50dcf053"),
    (450000, "d279277f8f846a224d776450aa04da3cf978991a182c6f3075db4c48b173bbd7"),
    (771275, "1b7d789ed82cbdc640952e7e7a54966c6488a32eaad54fc39dff83f310dbaaed"),
    (1000000, "6aae55bea74235f0c80bd066349d4440c31f2d0f27d54265ecd484d8c1d11b47"),
    (1250000, "00c7a442055c1a990e11eea5371ca5c1c02a0677b33cc88ec728c45edc4ec060"),
    (1500000, "f1d32d6920de7b617d51e74bdf4e58adccaa582ffdc8657464454f16a952fca6"),
    (1750000, "5c8e7327984f0d6f59447d89d143e5f6eafc524c82ad95d176c5cec082ae2001"),
    (2000000, "9914f0e82e39bbf21950792e8816620d71b9965bdbbc14e72a95e3ab9618fea8"),
    (2031142, "893297d89afb7599a3c571ca31a3b80e8353f4cf39872400ad0f57d26c4c5d42"),
    (2250000, "0a87a8d4e40dca52763f93812a288741806380cd569537039ee927045c6bc338"),
    (2510150, "77e3f4a4bcb4a2c15e8015525e3d15b466f6c022f6ca82698f329edef7d9777e"),
    (2750000, "d4f8abb835930d3c4f92ca718aaa09bef545076bd872354e0b2b85deefacf2e3"),
    (3000000, "195a83b091fb3ee7ecb56f2e63d01709293f57f971ccf373d93890c8dc1033db"),
    (3250000, "7f3e28bf9e309c4b57a4b70aa64d3b2ea5250ae797af84976ddc420d49684034"),
    (3500000, "eaa303b93c1c64d2b3a2cdcf6ccf21b10cc36626965cc2619661e8e1879abdfb"),
    (3606083, "954c7c66dee51f0a3fb1edb26200b735f5275fe54d9505c76ebd2bcabac36f1e"),
    (3854173, "e4b4ecda4c022406c502a247c0525480268ce7abbbef632796e8ca1646425e75"),
    (3963597, "2b6927cfaa5e82353d45f02be8aadd3bfd165ece5ce24b9bfa4db20432befb5d"),
    (4303965, "ed7d266dcbd8bb8af80f9ccb8deb3e18f9cc3f6972912680feeb37b090f8cee0"),
    (5050000, "e7d4577405223918491477db725a393bcfc349d8ee63b0a4fde23cbfbfd81dea"),
];

/// DogecoinTestnet checkpoints.
#[rustfmt::skip]
pub const DOGECOINTESTNET: &[(u64, &str)] = &[
    (0, "bb0a78264637406b6360aad926284d544d7049f45189db5664f3c4d07350559e"),
    (483173, "a804201ca0aceb7e937ef7a3c613a9b7589245b10cc095148c4ce4965b0b73b5"),
    (591117, "5f6b93b2c28cedf32467d900369b8be6700f0649388a7dbfd3ebd4a01b1ffad8"),
    (658924, "ed6c8324d9a77195ee080f225a0fca6346495e08ded99bcda47a8eea5a8a620b"),
    (703635, "839fa54617adcd582d53030a37455c14a87a806f6615aa8213f13e196230ff7f"),
    (1000000, "1fe4d44ea4d1edb031f52f0d7c635db8190dc871a190654c41d2450086b8ef0e"),
    (1202214, "a2179767a87ee4e95944703976fee63578ec04fa3ac2fc1c9c2c83587d096977"),
    (1250000, "b46affb421872ca8efa30366b09694e2f9bf077f7258213be14adb05a9f41883"),
    (1500000, "0caa041b47b4d18a4f44bdc05cef1a96d5196ce7b2e32ad3e4eb9ba505144917"),
    (1750000, "8042462366d854ad39b8b95ed2ca12e89a526ceee5a90042d55ebb24d5aab7e9"),
    (2000000, "d6acde73e1b42fc17f29dcc76f63946d378ae1bd4eafab44d801a25be784103c"),
    (2250000, "c4342ae6d9a522a02e5607411df1b00e9329563ef844a758d762d601d42c86dc"),
    (2500000, "3a66ec4933fbb348c9b1889aaf2f732fe429fd9a8f74fee6895eae061ac897e2"),
    (2750000, "473ea9f625d59f534ffcc9738ffc58f7b7b1e0e993078614f5484a9505885563"),
    (3062910, "113c41c00934f940a41f99d18b2ad9aefd183a4b7fe80527e1e6c12779bd0246"),
    (3286675, "07fef07a255d510297c9189dc96da5f4e41a8184bc979df8294487f07fee1cf3"),
    (3445426, "70574db7856bd685abe7b0a8a3e79b29882620645bd763b01459176bceb58cd1"),
    (3976284, "af23c3e750bb4f2ce091235f006e7e4e2af453d4c866282e7870471dcfeb4382"),
    (5900000, "199bea6a442310589cbb50a193a30b097c228bd5a0f21af21e4e53dd57c382d3"),
];
