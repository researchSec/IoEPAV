require("@nomiclabs/hardhat-waffle");
/**
 * @type import('hardhat/config').HardhatUserConfig
 */

// Go to https://www.alchemyapi.io, sign up, create
// a new App in its dashboard, and replace "KEY" with its key
const ALCHEMY_API_KEY_RINKEY = "";
const ALCHEMY_API_KEY_ROPSTEN = "";
// Replace this private key with your Ropsten account private key
// To export your private key from Metamask, open Metamask and
// go to Account Details > Export Private Key
// Be aware of NEVER putting real Ether into testing accounts
const TESTNET_PRIVATE_KEY = [];

const TESTNET_PRIVATE_KEY2 = [];

module.exports = {
  solidity: "0.7.3",
  networks: {
    rinkeby: {
      url: `https://eth-rinkeby.alchemyapi.io/v2/${ALCHEMY_API_KEY_RINKEY}`,
      accounts: TESTNET_PRIVATE_KEY
    },
    ropsten: {
      url: `https://eth-ropsten.alchemyapi.io/v2/${ALCHEMY_API_KEY_ROPSTEN}`,
      accounts: TESTNET_PRIVATE_KEY2
    },
    hardhat: {
      accounts: {
        count:51
      }
    }
  }
};