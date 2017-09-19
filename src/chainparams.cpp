// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "base58.h"

using namespace std;

#include "chainparamsseeds.h"

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "APIA";
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        /**
         * The message start string should be awesome! ⓩ❤
        pchMessageStart[0] = 0x24;
        pchMessageStart[1] = 0xe9;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0x64;
        */
        pchMessageStart[0] = 0x52;
        pchMessageStart[1] = 0x15;
        pchMessageStart[2] = 0x13;
        pchMessageStart[3] = 0x43;
        vAlertPubKey = ParseHex("04b7ecf0baa90495ceb4e4090f6b2fd37eec1e9c85fac68a487f3ce11589692e4a317479316ee814e066638e1db54e37a10689b70286e6315b1087b6615d179264");
        nDefaultPort = 8666;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        /**
         * Build the genesis block. Note that the output of its generation
         * transaction cannot be spent since it did not originally exist in the
         * database (and is in any case of zero value).
         *
         * >>> from pyblake2 import blake2s
         * >>> 'Zcash' + blake2s(b'The Economist 2016-10-29 Known unknown: Another crypto-currency is born. BTC#436254 0000000000000000044f321997f336d2908cf8c8d6893e88dbf067e2d949487d ETH#2521903 483039a6b6bd8bd05f0584f9a078d075e454925eb71c1f13eaff59b405a721bb DJIA close on 27 Oct 2016: 18,169.68').hexdigest()
         */
        const char* pszTimestamp = "Apiab805da8655d8354657ad5c32ec1aece0ca985dcb649c767ebceb7d61f5150956";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock.SetNull();
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 4;
        genesis.nTime    = 1502383005;
        genesis.nBits    = 0x1f07ffff;
        genesis.nNonce   = uint256S("0x000000000000000000000000000000000000000000000000000000000000011a");
        genesis.nSolution = ParseHex("0064bc3b3c42fb94a73593ed8578a54ac1375a82f228f5b36e28da4e66e43d33e35b31521952a1dc45210c6d42bfe0e5b2fda8715408497d2fdf32717b89c0102a1a384dcda65335fe8b9d1ddff5374b631b1237046633a8fd017732efc4222b43ab0bc8f58b76709e0ee6b31ebb1953a93dd9778686c6ceb249f1129ccf07b5ca09ed64f8b3a4f640c9d6173b2963a97f853d16f8cf21235a0c68e56402476beace15e17b5c02fb00c99c29f0db581377c93054d5aee2306af53b813350e27e10f2e4b0c3feeff5f359696965cf0bdcc85201d7b52e5f08dc60de0fa0a449c3c2109a1498fd1f3b2887bd6d536f6dbaaf44c10adb50e2ce48ff3c7107101ce037d56825d7a281f82c658ce4d32dbf4a0816d8d9ebddcb0d7b9452b34492f8de296b9359cb792f2b9f9a66562056fb1b139cc3e2fd0e5cbdb7a52a53b8f65cd6e124d5ec0118302bf66f43adb21e32770155405382478132aa30a425b126452d263e6d7022127665b4b74c85be8d6f13ae99436f96eb6e17afb90a7cedc0fdc70401e8d02399b6466e1abafcf61d7a36b44f2a6a2724f189aa488372e6155372853f78ed0dbb1b2029e363d19134827524e31744c28594ed1a483485ab3a6acf4f75aab6f02ae962a3b4a3bf79672359d6f0f2d7ef03a1e484c102527dc2bdc7fc748d8217af8f61a80f7777f7e95e9e562f26e0251ee5520456323a1aa275316ddb20c6937106f89188c4fa8e11cf179a5644cdb9afdce3300acc18ed109256452006a590df27914e9a8b8b89971feb83467ee85fddd4097271d97bd1a9a5f1c23780a0f569b6143cf72c4f0ea07c3a7d8ce8bad4ee71d779eaf5598a786f35602e6cef60e455dd1d365a764f58d8bd2398f47d67b4194c1722038a82f9bc01f2b9e5652a79d5ac1301c542d4bf6d07e272551b902c262e78f08795ca9fd2d7007576cb8fd29ff3e6b7433de0b2837f66a07be6f911628d2fe9d1b77caf2dd178d3f38008fa78fd9eef1445aa6a3a2f3d63b07563624647e7965cfddd6ade43ef5b1bf2943e67b8b906546bb9842242ec125e2209d19072880ab20d4b6ba0d2570d4e61bbdc37df5b1f8f1c01475d9e957d43b21cfa73a70b1e3e3e8deb1af7d3964d59195cdd83943cca502691328b89e9c41e4a2cb5ac09d929997202ec6e4188c0d0d43a2c5001e87f38a18e308478b9f23df776b73203ebb33f0c2f9a320b45213bd59b4e0690da5c6b76ecc3dda29109fdf17f81072e5b6026f365cc9b51eda4094e57f617c09cd16625591bbf5465876f4975cd74c24be3180a2737256418b43fc188449375d89e1afbe17b78bc0c17e6ea8ae70aa7f97d68b8e376e6933c0a5d06bd1426d664d985ee9f3599b326d99e0c2744847f4e1315671ed66f899383ac66429a304e304198620d233c02687c9fc5777439bc70a0acbf5ebfa6271275627d072b993173696247fec372f53ff25b7cc9d536821c0726bf32431b3693a03a4619e1ce7e6e3e4a1d48ed0c3872802284bf4f938e63104b7e5979402beef0f90635e097e068e10bb9212337766ddd0e6157baf32906566c2871224155db42107782ce493a424bfe14d90d4344d8879f5d97673ee6da3e7e452a5d0f36d8111228314f07602b81d68332cd6eba04432ce09c575908a5ca6c58469d684ae9e2d820b6254196b3ad479217f018f9d9abe505795fb3038ad54f7f2cfdb979d617c647acbe879f324bc89356e75e66917cbfb54e832895bc801ba05d37950f84f2c86ca10dfcd676ec5008a7799af6d426e0c76312c9b8ca2f9cce9b77d1711baa2ff7fdddbc1b5c8db25ec7abe9fdbb433e9d0b15c8edb4d153a546f2f875ad86e7dff58e99b4bf981f17ca0ef71917bbab0284f40569a56e3fd5ffb3b3");

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("00051b00da991d836ad8fd15ea2f8f90493ae0f6a2c41927182340f4f70236ac"));
        assert(genesis.hashMerkleRoot == uint256S("0xd2f45d99adbae82f4a0dd10a4bf8766be69f87bd058b8e2d836c9aa1c2b69c2c"));

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("masternode", "apia.network")); 
        vSeeds.push_back(CDNSSeedData("node1", "52.191.161.211")); 
        vSeeds.push_back(CDNSSeedData("node2", "158.69.252.111")); 
        vSeeds.push_back(CDNSSeedData("node3", "40.84.227.209")); 

        // guarantees the first 2 characters, when base58 encoded, are "t1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1C,0xB8};
        // guarantees the first 2 characters, when base58 encoded, are "t3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBD};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock),
	     //(11, uint256S("000187e0361de1f7b905003ee5772ad5b8203cc7e6dbb2799f60d7725e56ea93")),
            1502383005, // time of last CP 1502786987,
            0, // number of txns since last CP
            100 
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
            "t3hLJHrHs3ytDgExxr1mD8DYSrk1TowGV25", /* main-index: 51*/
            "t3fmYHU2DnVaQgPhDs6TMFVmyC3qbWEWgXN"  /* main-index: 52*/
				};
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TAZ";
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.fPowAllowMinDifficultyBlocks = true;
        pchMessageStart[0] = 0x27;
        pchMessageStart[1] = 0x52;
        pchMessageStart[2] = 0x1b;
        pchMessageStart[3] = 0x17;
        vAlertPubKey = ParseHex("044e7a1553392325c871c5ace5d6ad73501c66f4c185d6b0453cf45dec5a1322e705c672ac1a27ef7cdaf588c10effdf50ed5f95f85f2f54a5f6159fca394ed0c6");
        nDefaultPort = 18667;
        nPruneAfterHeight = 1000;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1477648033;
        genesis.nBits = 0x2007ffff;
        genesis.nNonce = uint256S("0x000000000000000000000000000000000000000000000000000000000000061d");
        genesis.nSolution = ParseHex("00487b96ee2abd03e85c1017d140d7052dd47d96b82209578b4859a571640ff4ee5dfc10c5c85d5308b7054e2880aa8313ec7de692dcc19df53659583f88260f5a68c144244e85dbc772527a55fb4d3b17eef7af2f9b9ce508d06fe7d4d373e5cbf30162c470db2dc9849cefbcd7a746b7dbabeb93d37fbfabb3a91dc56d345e9214f42bb42f9899437f524970eb1757fe3eff533eb4133bd671f54cfc95cd023a36ea38fb161adf03f92638bc2e68fbe2dbc1bb66e89421c6270e6b7a28cc7564b269c3c9e9aca3d33b490db57e67d7bda60895bf819dc63333760d6208f1fd81ed32f79adfbe0cdb15a031f1950db7ae4c2945effac7e4859fdddc0648131764948215b9e6a1beca98ee890c987bc9ef0a9d42c03f1196b9128db57894fd49629952bea0811e8ab9cabc0b379bef5ea53fccfc07be0ad433d0db47596449816207bbe0139480eb6ee6056fee1c9a5d066d8e5ddecd207344ced2d7a0c2258dfc3dbb881b27154fc2d2e1dfd3d6823368d1e922397365b109a50f30ed2c16938e7b0c7751ff513f17737c54ddddf7265aad4a67e0597d8db5739b7cfe5e99ffd373f60b08b67bc0caca6f20599ae149f03edd59977cba883020189b47f36a4057d5cea216012c4cfd72ca4c2f000d4329cefeb32ce9ec1df4e78cdb02ba1f515fdf712cf3fa2f7099ab69d33583a9f6d2b45f5d84fc358a08987206b5c6630f690cc0bdce062c0da0676d76a80f1791c77468e891d470f573e6e79b65bf2edcd9b32c8c996c484d148ad6b6c30b834e740dea891de285401ece0390a997bd88c888837dce8c3f785adf86b01a2391aeb1e0fa7d3a71d309cd36af7d4860f1a8e42369ffaf634c9ba52b9dd291f09b082a6fc9b73e8a4e43d5f1a058ffc0fd9a2502a867a6f724d45c69dd633e5369a3b55003d7185ae33cf56d137a7ebd565400de2bb16bc6e4bad7ab75ba1d7e2eaa1a8c9fd2a223ae9ee59b4ad38987d7a3d8c84d198954d0b8d3ab307c72bfc91d10f707ef631d706d77738e091ed0953ed40abd17e8cf7bdff044f8dedf1c8a56d4bb0d5a24363fb8fb8954adbc8ee76a8d63aa11ec75165d303f66f72d8a9dd541a9f5950705cb09d2ea143f707e2528e2d21db39f47f09ba2a5699d00526abbdbcf103d59a279379c2b8945c16637e355adf9f9355399a005d265b1a9f96f3bfbfd588b98fb028aa911d861bd46f356b9455e3559f716280a78ca9eba2cb0f9a224149a2c7fc148e05b5e31b26a0fd0d5c2fb1f9d2dc3199c5c5c3eed8f43e72c63993f31e20b57013e332207ab4974c295d3733ce499641256aa7ea7d937a9560cf6920b05a68e1bb65f9226053963cd306a102d211eb158f72827219d545c4260397fb37b77e41c7e8241358c38572474bf6e87b45004759dae5995551e0302eac2b55a4463c038fca0452fe5235c178fea60a316bec8f5170dd837370d1ae595f4bf66fb6bbea6382eb66e45538c8840ff03f4d53de4dd3a6b0e743b152fd06cd3cbcdc3c75d598653e3fc0e11e62693584606f533801eae3509ff53a10b6b7cd439c965b05bef4299ef57b162626565bdc67ca7cd5c8f1d051c70d4083e55406404b9222f21d46a5d3e5a8276787f76f32ef09979934f65ded614f64408fada05ddbf7da76c070660a3d0c948bebd9bba28c6d95a8b362abbd2a436d689fdb56523753a5de4f9d2b7fd7961a45163e4090a21a443c730d256be3138050de46f65bf7d0aa40ad89256586e3af97b9099fe4afd287f3b177aad7207519201d2d3275dc06c13feecec41dba12d7e8c953c0cb9f28395711517fda8efc878a90a42edfed3011ead8b05875214e6af3f551d144002b5a68719f7fc25fdcd4a3be819d392f5291cd7683a0e96d8171b22");
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("38c0dbcee117e5373e216943a3d837d500821f23098f222330ab66770dd2ae0c"));

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("z.cash", "dnsseed.testnet.z.cash")); // Zcash

        // guarantees the first 2 characters, when base58 encoded, are "tm"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        // guarantees the first 2 characters, when base58 encoded, are "t2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

	checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock),
            genesis.nTime,
            0,
            0
        };
        // Founders reward script expects a vector of 2-of-3 multisig addresses
	vFoundersRewardAddress = { "t2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg" };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nMaxTipAge = 24 * 60 * 60;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
        genesis.nTime = 1296688602;
        genesis.nBits = 0x200f0f0f;
        genesis.nNonce = uint256S("0x0000000000000000000000000000000000000000000000000000000000000009");
        genesis.nSolution = ParseHex("01936b7db1eb4ac39f151b8704642d0a8bda13ec547d54cd5e43ba142fc6d8877cab07b3");
        consensus.hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 18344;

        assert(consensus.hashGenesisBlock == uint256S("0a237389ee8b14f083db1bc5f514607bd7b6a92eaab92baa9297aa9e8ec5ae33"));
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (Checkpoints::CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")),
            0,
            0,
            0
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = { "t2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg" };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CBitcoinAddress address(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(address.IsValid());
    assert(address.IsScript());
    CScriptID scriptID = get<CScriptID>(address.Get()); // Get() returns a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}
