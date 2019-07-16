import argparse
from getpass import getpass
import json

import aergo.herapy as herapy

from web3 import (
    Web3,
)
from web3.middleware import (
    geth_poa_middleware,
)

from ethaergo_wallet.eth_utils.contract_deployer import (
    deploy_contract,
)


def deploy_bridge(
    config_path: str,
    lua_bytecode_path: str,
    sol_bytecode_path: str,
    bridge_abi_path: str,
    minted_erc20_abi_path: str,
    t_anchor_eth: int,
    t_anchor_aergo: int,
    eth_finality: int,
    eth_net: str,
    aergo_net: str,
    aergo_erc20: str = 'aergo_erc20',
    privkey_name: str = None,
    privkey_pwd: str = None,
) -> None:
    """ Deploy brige contract on Aergo and Ethereum."""

    with open(config_path, "r") as f:
        config_data = json.load(f)
    with open(lua_bytecode_path, "r") as f:
        lua_bytecode = f.read()[:-1]
    with open(sol_bytecode_path, "r") as f:
        sol_bytecode = f.read()
    with open(bridge_abi_path, "r") as f:
        bridge_abi = f.read()
    if privkey_name is None:
        privkey_name = 'proposer'
    print("------ DEPLOY BRIDGE BETWEEN Aergo & Ethereum -----------")

    print("------ Connect AERGO -----------")
    aergo = herapy.Aergo()
    aergo.connect(config_data['networks'][aergo_net]['ip'])
    print("------ Connect Web3 -----------")
    ip = config_data['networks'][eth_net]['ip']
    w3 = Web3(Web3.HTTPProvider("http://" + ip))
    eth_poa = config_data['networks'][eth_net]['isPOA']
    if eth_poa:
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    assert w3.isConnected()

    status = aergo.get_status()
    height = status.best_block_height
    lib = status.consensus_info.status['LibNo']
    # aergo finalization time
    t_final_aergo = height - lib
    print("aergo finality: ", t_final_aergo)
    print("ethereum finality: ", eth_finality)

    print("------ Set Sender Account -----------")
    if privkey_pwd is None:
        privkey_pwd = getpass("Decrypt Aergo private key '{}'\nPassword: "
                              .format(privkey_name))
    sender_priv_key = config_data['wallet'][privkey_name]['priv_key']
    aergo.import_account(sender_priv_key, privkey_pwd)
    print("  > Sender Address Aergo: {}".format(aergo.account.address))

    keystore = config_data["wallet-eth"][privkey_name]['keystore']
    with open(keystore, "r") as f:
        encrypted_key = f.read()
    if privkey_pwd is None:
        privkey_pwd = getpass("Decrypt Ethereum keystore '{}'\nPassword: "
                              .format(privkey_name))
    privkey = w3.eth.account.decrypt(encrypted_key, privkey_pwd)
    acct = w3.eth.account.from_key(privkey)
    sender = acct.address
    print("  > Sender Address Ethereum: {}".format(sender))

    # get validators from config file
    aergo_validators = []
    eth_validators = []
    for validator in config_data['validators']:
        eth_validators.append(Web3.toChecksumAddress(validator['eth-addr']))
        aergo_validators.append(validator['addr'])
    print('aergo validators : ', aergo_validators)
    print('ethereum validators : ', eth_validators)

    print("------ Deploy Aergo SC -----------")
    payload = herapy.utils.decode_address(lua_bytecode)
    aergo_erc20_addr = config_data['networks'][eth_net]['tokens'][aergo_erc20]['addr']
    tx, result = aergo.deploy_sc(amount=0,
                                 payload=payload,
                                 args=[aergo_erc20_addr[2:].lower(),
                                       aergo_validators,
                                       t_anchor_aergo,
                                       eth_finality])
    if result.status != herapy.CommitStatus.TX_OK:
        print("    > ERROR[{0}]: {1}"
              .format(result.status, result.detail))
        aergo.disconnect()
        return
    print("    > result[{0}] : {1}"
          .format(result.tx_id, result.status.name))

    result = aergo.wait_tx_result(tx.tx_hash)
    if result.status != herapy.TxResultStatus.CREATED:
        print("  > ERROR[{0}]:{1}: {2}"
              .format(result.contract_address, result.status,
                      result.detail))
        aergo.disconnect()
        return
    aergo_bridge = result.contract_address

    print("------ Deploy Ethereum SC -----------")
    receipt = deploy_contract(
        sol_bytecode, bridge_abi, w3, 6700000, 20, privkey,
        eth_validators,
        t_anchor_eth, t_final_aergo
    )
    eth_bridge = receipt.contractAddress

    print("  > SC Address Ethereum: {}".format(eth_bridge))
    print("  > SC Address Aergo: {}".format(aergo_bridge))

    print("------ Store bridge addresses in test_config.json  -----------")
    config_data['networks'][eth_net]['bridges'][aergo_net] = {}
    config_data['networks'][aergo_net]['bridges'][eth_net] = {}
    (config_data['networks'][eth_net]['bridges'][aergo_net]
        ['addr']) = eth_bridge
    (config_data['networks'][aergo_net]['bridges'][eth_net]
        ['addr']) = aergo_bridge
    (config_data['networks'][eth_net]['bridges'][aergo_net]
        ['t_anchor']) = t_anchor_eth
    (config_data['networks'][eth_net]['bridges'][aergo_net]
        ['t_final']) = t_final_aergo
    (config_data['networks'][aergo_net]['bridges'][eth_net]
        ['t_anchor']) = t_anchor_aergo
    (config_data['networks'][aergo_net]['bridges'][eth_net]
        ['t_final']) = eth_finality
    (config_data['networks'][eth_net]['bridges'][aergo_net]
        ['bridge_abi']) = bridge_abi_path
    (config_data['networks'][eth_net]['bridges'][aergo_net]
        ['minted_abi']) = minted_erc20_abi_path

    with open(config_path, "w") as f:
        json.dump(config_data, f, indent=4, sort_keys=True)

    print("------ Disconnect AERGO -----------")
    aergo.disconnect()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Deploy bridge contracts between Ethereum and Aergo.')
    # Add arguments
    parser.add_argument(
        '-c', '--config_file_path', type=str, help='Path to config.json',
        required=True)
    parser.add_argument(
        '-a', '--aergo', type=str, help='Name of Aergo network in config file',
        required=True)
    parser.add_argument(
        '-e', '--eth', type=str, help='Name of Ethereum network in config file',
        required=True)
    parser.add_argument(
        '--privkey_name', type=str, help='Name of account in config file '
        'to sign anchors', required=False)

    args = parser.parse_args()
    # eth_net = 'eth-poa-local'
    # aergo_net = 'aergo-local'
    # config_path = "./test_config.json"
    lua_bytecode_path = "./contracts/lua/bridge_bytecode.txt"
    sol_bytecode_path = "./contracts/solidity/bridge_bytecode.txt"
    minted_erc20_abi_path = "./contracts/solidity/minted_erc20_abi.txt"
    bridge_abi_path = "./contracts/solidity/bridge_abi.txt"

    # NOTE t_final is the minimum time to get lib : only informative (not
    # actually used in code except for Eth bridge because Eth doesn't have LIB)
    t_anchor_eth = 7  # aergo anchoring periord on ethereum
    t_anchor_aergo = 6  # ethereum anchoring periord on aergo
    eth_finality = 4  # blocks after which ethereum is considered finalized
    deploy_bridge(
        args.config_file_path, lua_bytecode_path, sol_bytecode_path,
        bridge_abi_path, minted_erc20_abi_path, t_anchor_eth,
        t_anchor_aergo, eth_finality, args.eth, args.aergo,
        'aergo_erc20', privkey_name=args.privkey_name
    )
