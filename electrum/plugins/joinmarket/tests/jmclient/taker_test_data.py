# -*- coding: utf-8 -*-


# orderbook
t_orderbook = [
    {
        'counterparty': 'J6FA1Gj7Ln4vSGne', 'ordertype': 'sw0reloffer',
        'oid': 0, 'minsize': 75000, 'txfee': 1000, 'maxsize': 599972700,
        'cjfee': '0.00002'},
    {
        'counterparty': 'J6CFffuuewjG44UJ', 'ordertype': 'sw0reloffer',
        'oid': 0, 'minsize': 75000, 'txfee': 1000, 'maxsize': 599972700,
        'cjfee': '0.00002'},
    {
        'counterparty': 'J65z23xdjxJjC7er', 'ordertype': 'sw0reloffer',
        'oid': 0, 'minsize': 75000, 'txfee': 1000, 'maxsize': 599972700,
        'cjfee': '0.00002'},
    {
        'counterparty': 'J64Ghp5PXCdY9H3t', 'ordertype': 'sw0reloffer',
        'oid': 0, 'minsize': 75000, 'txfee': 1000, 'maxsize': 599972700,
        'cjfee': '0.00002'},
    {
        'counterparty': 'J659UPUSLLjHJpaB', 'ordertype': 'sw0reloffer',
        'oid': 0, 'minsize': 75000, 'txfee': 1000, 'maxsize': 599972700,
        'cjfee': '0.00002'},
    {
        'counterparty': 'J6cBx1FwUVh9zzoO', 'ordertype': 'sw0reloffer',
        'oid': 0, 'minsize': 75000, 'txfee': 1000, 'maxsize': 599972700,
        'cjfee': '0.00002'}]


t_dest_addr = "mvw1NazKDRbeNufFANqpYNAANafsMC2zVU"


t_chosen_orders = {
    'J659UPUSLLjHJpaB': {
        'cjfee': '0.0002', 'counterparty': 'J659UPUSLLjHJpaB',
        'maxsize': 599972700, 'minsize': 75000, 'oid': 0,
        'ordertype': 'sw0reloffer', 'txfee': 1000},
    'J65z23xdjxJjC7er': {
        'cjfee': '0.0002', 'counterparty': 'J65z23xdjxJjC7er',
        'maxsize': 599972700, 'minsize': 75000, 'oid': 0,
        'ordertype': 'sw0reloffer', 'txfee': 1000},
    'J6CFffuuewjG44UJ': {
        'cjfee': '0.0002', 'counterparty': 'J6CFffuuewjG44UJ',
        'maxsize': 599972700, 'minsize': 75000, 'oid': 0,
        'ordertype': 'sw0reloffer', 'txfee': 1000}}


"""
total cj fee = 63000
total coinjoin fee = 0.0573%
INFO:Preparing bitcoin data..
rpc: getaccount ['myzi6K9vt88rdiXpYayfJkU1x33G1wz2fP']
total estimated amount spent = 110093000
"""


t_utxos_by_mixdepth = {
    0: {
        'b82763a40e3c701669cb57341a8116d7f6d4cd2dbd0648d839c6b754aac37dd2:4': {
            'address': 'tb1qs33rq0wmrq2awvuxrte0mqkksvzr6x9sdkrfdc',
            'value': 2500000}},
    1: {
        'b82763a40e3c701669cb57341a8116d7f6d4cd2dbd0648d839c6b754aac37dd2:3': {
            'address': 'tb1q8c2k82wyzcxgk3x2257r2j6ngzedvjppdh4904',
            'value': 2500000},
        'b82763a40e3c701669cb57341a8116d7f6d4cd2dbd0648d839c6b754aac37dd2:1': {
            'address': 'tb1qpjkqrhz3kxsg93c5cw2axhdy39wqy36u9ygzdk',
            'value': 2500000},
        'b82763a40e3c701669cb57341a8116d7f6d4cd2dbd0648d839c6b754aac37dd2:2': {
            'address': 'tb1q8qymfhts46zngpnve4rf6mjaqg398ggskvw3ez',
            'value': 2500000}},
    2: {},
    3: {},
    4: {}}


t_selected_utxos = [{  # 1 0
    'utxo': 'b82763a40e3c701669cb57341a8116d7'
            'f6d4cd2dbd0648d839c6b754aac37dd2:2',
    'value': 2500000}]


t_generated_podle = {
    'P': '025a2e04dc6bd5f58fe4eb13045b27f0dd17c39524264639f48607347cf6d69c4e',
    'P2': '0223e54e9917d8482f1b54ead8e941907c17051b95397e8bc110adc6681d8d44c8',
    'commit': 'aa0545c9ed918e66f86df467c96a4978'
              '529b836aa4688df682a2db4e27d4ed9d',
    'e': '5b7ab1fa21287bbf0df4a0c46f6c31c3f17887ee9ea6ae584fc3a861ae9f1e9d',
    'sig': 'ebe25d7b2d667de802677c30c6fea07386f0cd67d4e4c795e4a6ebc39b21eb39',
    'used': 'False',
    'utxo': '0780d6e5e381bff01a3519997bb4fcba'
            '002493103a198fde334fd264f9835d75:1'}


t_maker_response = {
    "J659UPUSLLjHJpaB": [
        ["03243f4a659e278a1333f8308f6aaf32db4692ee7df0340202750fd6c09150f6:1"],
        "03a2d1cbe977b1feaf8d0d5cc28c686859563d1520b28018be0c2661cf1ebe4857",
        "mrKTGvFfYUEqk52qPKUroumZJcpjHLQ6pn",
        "mxPnzFkCQpPzVQdajNLoT4us5pTPsQZZZp",
        "MEQCIBeGrtxxVrj5tSUX6vEetmzE8nRBG/guSXq3SrqypIt5AiAnIZzDUXu8DtODgF2p"
        "1Bo27L8VcG1GJSfatZbS23YZQQ==",
        "5bcc7ae1a3530e454812668620aced47d774bf06a1f5870d531422a1a958b629"],
    "J65z23xdjxJjC7er": [
        ["498faa8b22534f3b443c6b0ce202f31e12f21668b4f0c7a005146808f250d4c3:0"],
        "02b4b749d54e96b04066b0803e372a43d6ffa16e75a001ae0ed4b235674ab286be",
        "mhatyHdna3Qt5FtnfwWaMVV1dohCaDYF3T",
        "mjJoVN2HCUGVDvNebiFnHdB3zF56bxQm5z",
        "MEQCIBlMF7DRbhr14e74He9m+UYjR5y8jjvP7TvUh8valebmAiBoIGjl436fsYim9pKS"
        "TbCKiBmT82hQ98LvIOGSLprk0A==",
        "8204d1cba30d4cdabab16a5e8d10d17464e24c78a6f887ae2d920b223c030d28"],
    "J6CFffuuewjG44UJ": [
        ["3f3ea820d706e08ad8dc1d2c392c98facb1b067ae4c671043ae9461057bd2a3c:1"],
        "023bcbafb4f68455e0d1d117c178b0e82a84e66414f0987453d78da034b299c3a9",
        "mpAEocXy8ckcJBo3fhQg9Mv1kfEzAuUivX",
        "n29NWbsyq5MjCMC5ykjStd78zwfjvCvJJZ",
        "MEUCIQDAM5Aa0aU5iKI0b9YnNtwH0m+6sz3zeTL8f398CPjuQAIgLeU9mCJX8SupNNMk"
        "A+bsUJeRYe3kiLnzq3OlmXTxck0=",
        "7377d03477485884e0129dbdb2d79f4956f5b74366d805385b6f127509a8433f"]}

"""
rpc: gettxout
['03243f4a659e278a1333f8308f6aaf32db4692ee7df0340202750fd6c09150f6', 1, False]
fee breakdown for J659UPUSLLjHJpaB totalin=2500000 cjamount=110000000
txfee=1000 realcjfee=22000
rpc: gettxout
['498faa8b22534f3b443c6b0ce202f31e12f21668b4f0c7a005146808f250d4c3', 0, False]
fee breakdown for J65z23xdjxJjC7er totalin=2500000 cjamount=110000000
txfee=1000 realcjfee=22000
rpc: gettxout
[3f3ea820d706e08ad8dc1d2c392c98facb1b067ae4c671043ae9461057bd2a3c', 1, False]
fee breakdown for J6CFffuuewjG44UJ totalin=2500000 cjamount=110000000
txfee=1000 realcjfee=22000
INFO:Got all parts, enough to build a tx
Estimated transaction size: 870
rpc: estimatefee [3]
got estimated tx bytes: 870
Based on initial guess: 30000, we estimated a miner fee of: 26100
fee breakdown for me totalin=2500000 my_txfee=23100 makers_txfee=3000
cjfee_total=66000 => changevalue=89910900
"""


t_obtained_tx = {
    'ins': [
        {'outpoint': {'hash': '03243f4a659e278a1333f8308f6aaf32'
                              'db4692ee7df0340202750fd6c09150f6',
                      'index': 1},
         'script': '',
         'sequence': 4294967295},
        {'outpoint': {'hash': '3f3ea820d706e08ad8dc1d2c392c98fa'
                              'cb1b067ae4c671043ae9461057bd2a3c',
                      'index': 1},
         'script': '',
         'sequence': 4294967295},
        {'outpoint': {'hash': '498faa8b22534f3b443c6b0ce202f31e'
                              '12f21668b4f0c7a005146808f250d4c3',
                      'index': 0},
         'script': '',
         'sequence': 4294967295},
        {'outpoint': {'hash': '0780d6e5e381bff01a3519997bb4fcba'
                              '002493103a198fde334fd264f9835d75',
                      'index': 1},
         'script': '',
         'sequence': 4294967295}],
    'locktime': 0,
    'outs': [
        {'script': '76a914767c956efe6092a775fea39a06d1cac9aae956d788ac',
         'value': 110000000},
        {'script': '76a914cab20e3270988ac99651b8f079a3b4c93b996a6888ac',
         'value': 89910900},
        {'script': '76a914b91f75254b5fa1510cc944a2206ed72235d0d88188ac',
         'value': 90021000},
        {'script': '76a914a916707952c2df28a3abf3ee692dfbbd5a4d74dc88ac',
         'value': 110000000},
        {'script': '76a914e245b480b46bcbc9d13e68766ad19909decd135288ac',
         'value': 90021000},
        {'script': '76a91416af241bb1db02dfd7c65989bbab190ac489ccc188ac',
         'value': 110000000},
        {'script': '76a9142994295a9d4d083eb792e669e3211007dc78928888ac',
         'value': 90021000},
        {'script': '76a9145ece2dac945c8ff5b2b6635360ca0478ade305d488ac',
         'value': 110000000}],
    'version': 1}


# signatures from makers
"""
nick=J6CFffuuewjG44UJ message=!sig
xH9IAMo2fvG+g+DAbLNOPsGsJCDm6r+ZY5QM7p+SRsixbqSwXcBQAn7Mnw1rS+uGlrJkM8ossX5VHKj
dKDhTXQVLawR7XgiVFFFiO+/FjdFhqVuS4Q/NgOlb7nCBe/UaBebd9NpuURG+8u/V+46jtqKRtVsSO1
+QZQBt2nSpYCqxWIjxMowRxS4O/zlrOVbyjv/AjchOajufKJwckkrkJDyQDYlUdW+eqs43tf0XsJ9k4
NHRVVHAQQ== 036558f550b1d398d2325d892e50ef25b0f663ae13f70d0b304a15f07030061ace
MEUCIQCE9MgU+HfcHkKE8zNzNeCEdDBJuQatA6C2sTJ9mVKK7wIgX4w9r0tz4s9qeuW0UjNliDatJ4X
7pS3/atADSqPat0U=
nick=J659UPUSLLjHJpaB message=!sig
geHTf1n88eKeUnVOj7bIrJF1KFCN03IQhZD0cR17Q7jPSn2DZrrvMaRNkjZRyF+zGnWFwd69kwLRU0f
tCaMf/3lw+05UovVCREiyXWUtPJa7XAY2NW4iMmTnGTp8f9RLgDcDhiZayKXTpzBDC9r6WAt6wiD0le
j5uw7dmluKSUyfXW8sOYPmLm4iJAPcbGeJiQfiR9zBeX8w+6Kz4bkaiue41SzQP/h9avPV2XIX4kVQQ
3jLfQyHww== 038f90ab260df440cef82a981146b509eb9df019884e145158230e8babc17d7be4
MEQCIEo5Pau9zqW2lw+B2AYTYuTO5TDbBkgsOk0bqT+SQctKAiBO1nbsmYTy7E0Qd7jAxko1Gq6Yk0Q
6DerByuEuk5IBSQ==
nick=J65z23xdjxJjC7er message=!sig
A5CWvqmYCOiZBEEi9iHVpQL0oO9B7VIIzuU9QhkzXOw+iD916C9b+Yk3eTxrtf+qaLARQ7eui6zdPNe
k95EdmqCEqM/myeeuBVSy9KrcB9xU0sdnuCu4+g13jVe9Pkvd1iizZ8GCNP7SejEzeltNr0a1lR+M0k
Ktj4XI+nDTxhisSzL8PDXsqoOMcrDjegna3TZsJeKviu8r/1T/zWwTQtRCXqruLnflqXNLtZoyFmoaO
1GurgkNHA== 029a8beadec242f04f2295787ac0175b960e2d68d115ec65c4310de7ce3fa2cec0
MEQCIHpTxVkwtvm7agbp47Z5V0We8jxXkfZDUFsW2tZwTZdHAiA9JnYvo74hF3RihzHw2l+ufTOmC/3
ddBpxkB9+AdZvzA==
"""


"""
INFO:Built tx, sending to counterparties.
rpc: gettxout
['03243f4a659e278a1333f8308f6aaf32db4692ee7df0340202750fd6c09150f6', 1, False]
rpc: gettxout
['3f3ea820d706e08ad8dc1d2c392c98facb1b067ae4c671043ae9461057bd2a3c', 1, False]
rpc: gettxout
['498faa8b22534f3b443c6b0ce202f31e12f21668b4f0c7a005146808f250d4c3', 0, False]
found good sig at index=1
nick = J6CFffuuewjG44UJ sent all sigs, removing from nonrespondant list
rpc: gettxout
['03243f4a659e278a1333f8308f6aaf32db4692ee7df0340202750fd6c09150f6', 1, False]
rpc: gettxout
['498faa8b22534f3b443c6b0ce202f31e12f21668b4f0c7a005146808f250d4c3', 0, False]
found good sig at index=0
nick = J659UPUSLLjHJpaB sent all sigs, removing from nonrespondant list
rpc: gettxout
['498faa8b22534f3b443c6b0ce202f31e12f21668b4f0c7a005146808f250d4c3', 0, False]
found good sig at index=2
nick = J65z23xdjxJjC7er sent all sigs, removing from nonrespondant list
all makers have sent their signatures
INFO:Transaction is valid, signing..
"""


t_raw_signed_tx = (
    "0100000004f65091c0d60f75020234f07dee9246db32af6a8f30f833138a279e654a3f240"
    "3010000006b483045022100ad522388ce9eacf2760e4d6bd6a114a0e15b88879b430fbb2e"
    "60df947494df2402201f49338726599eb0980873aef268d8d890de2792967ff28f0c11eb3"
    "5e54ff07a012103a2d1cbe977b1feaf8d0d5cc28c686859563d1520b28018be0c2661cf1e"
    "be4857ffffffff3c2abd571046e93a0471c6e47a061bcbfa982c392c1ddcd88ae006d720a"
    "83e3f010000006a473044022012bbfa6ef7b0416e00001d90b022d6663f5fd57d9a07bb70"
    "b887510f7c44902d022059b382bfb1ff5588a518fc69c55b2ff67d3facc11088e984d7c09"
    "c336d4875330121023bcbafb4f68455e0d1d117c178b0e82a84e66414f0987453d78da034"
    "b299c3a9ffffffffc3d450f208681405a0c7f0b46816f2121ef302e20c6b3c443b4f53228"
    "baa8f49000000006b48304502210081019ea7b68130da4230fd748668c776043004843de5"
    "0e07bb5fcb42e7632aed022000a34878274e583eec64815d1b587e7fbcd9ac714e722773a"
    "c1e69f1209f2e10012102b4b749d54e96b04066b0803e372a43d6ffa16e75a001ae0ed4b2"
    "35674ab286beffffffff755d83f964d24f33de8f193a10932400bafcb47b9919351af0bf8"
    "1e3e5d68007010000006b483045022100add68e9532a50ca5585999290531f26e515bdf3d"
    "001519b0de8dd6b981daec7f02200b34c58ce61e6673c9efc5bf82cacd4d02673bc1c6cba"
    "ba45b5c65579776b8180121025a2e04dc6bd5f58fe4eb13045b27f0dd17c39524264639f4"
    "8607347cf6d69c4effffffff0880778e06000000001976a914767c956efe6092a775fea39"
    "a06d1cac9aae956d788ac74ee5b05000000001976a914cab20e3270988ac99651b8f079a3"
    "b4c93b996a6888ac889c5d05000000001976a914b91f75254b5fa1510cc944a2206ed7223"
    "5d0d88188ac80778e06000000001976a914a916707952c2df28a3abf3ee692dfbbd5a4d74"
    "dc88ac889c5d05000000001976a914e245b480b46bcbc9d13e68766ad19909decd135288a"
    "c80778e06000000001976a91416af241bb1db02dfd7c65989bbab190ac489ccc188ac889c"
    "5d05000000001976a9142994295a9d4d083eb792e669e3211007dc78928888ac80778e060"
    "00000001976a9145ece2dac945c8ff5b2b6635360ca0478ade305d488ac00000000")


t_txid = "4d5bfad9bbfb93eb1e25fb2e6c832323d1bf39e63f6ed2319b65e85354c7ca70"


t_dummy_ext = {
    "used": [],
    "external": {
        "79f1b8df7d0978f30028487c6c4e0eae"
        "96d1aa18e01f13bb4cba6788590cd431:1": {
            "reveal": {
                "1": {
                    "P2": "0329d4b4bb28c1a0747c1a5daad59763"
                          "a9021b5e1fa957887a90c7849789a683b6",
                    "s": "a303cad939fb773dd16a81c44f210afe"
                         "0b985a2cf9a63b033139455b70c77be6",
                    "e": "64f5b9861b95434ab84bd044b93a28f8"
                         "5ea94b474237992d899bd4302eef3820"
                },
                "0": {
                    "P2": "02681ed66595daf98b12d6d69d8afb8d"
                          "14a531eeaea1161bce8b9f2666ea55f157",
                    "s": "ed994ad173431bd0f53c82fee70d202e"
                         "9c2adce492b6226d3cb4116cc3a08383",
                    "e": "1dd7f56fe83ca66e89b3ec3b73fa44ed"
                         "acab0ef4524652c415065dbf91500c85"
                },
                "2": {
                    "P2": "02cdd5ced7e79bdb651d6d1883e00475"
                          "09793a9a9e3da4ae516b8a853b9cdd8e98",
                    "s": "39a19287c4bacc823559d0e1b907e311"
                         "c31d8a13f45fe30d10b133561113515c",
                    "e": "a0e7cd319c7e51c6f9e503e95d08c3d2"
                         "398f9b546c2d64178b6c113c63c29d78"
                }
            },
            "P": "033749d513d0e0239a75892556a6ce01"
                 "c3e48f82e75169129abe8ef370ab992c94"
        }}}
