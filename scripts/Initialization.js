const { expect } = require("chai");
const crypto  = require('crypto');
const { ethers } = require("hardhat");
const  secp256k1 = require('secp256k1');
const myecc = require('./myecc');
function requester_gen_blind_c(m, R, P, gamaG, elta){

  let temppubKey  = new Uint8Array(33);
  if(myecc.publicKeyTweakMul(temppubKey, P,elta)) console.log("error at P*elta");
  const addtemp = [R, gamaG, temppubKey];
  if(myecc.publicKeyCombine(temppubKey,addtemp)) console.log("error at R+gamaG+P*elta");
  let Ax = new Uint8Array(32);
  if(myecc.getXpointFromPubkey(Ax,temppubKey)) console.log("error at getXpointFromPubkey");
  let hash = crypto.createHash('sha256');
  let c = Buffer.from(hash.update(m+myecc.getModn(Ax)).digest('hex'),'hex');
  c = myecc.getModn(c);
  let c_pi = new Uint8Array(32);
  if(myecc.blindC(c_pi,c,elta)) console.log("at c - elta");
  return {c:c, cpi: c_pi};
}



function signer_gen_blind_s(k, d, c_pi){
  let s_pi = new Uint8Array(32);
  if(myecc.bllindS(s_pi,k,c_pi,d)) console.log("error at k-c_pi*d");
  return s_pi;
}

function requester_gen_s_for_c(s_pi, gama){
  let s = new Uint8Array(32);
  if(myecc.openS(s,s_pi,gama)) console.log("error at s_pi + gama");
  return s;
}

function verify_blind_signature(m,c, P, s){
  let cP  = new Uint8Array(33);
  if(myecc.publicKeyTweakMul(cP, P,c)) console.log("error at cP");
  let sG  = new Uint8Array(33);
  if(myecc.publicKeyCreate(sG,s)) console.log("error at sG");
  let APK2  = new Uint8Array(33);
  const addtemp2 = [cP, sG];
  if(myecc.publicKeyCombine(APK2,addtemp2)) console.log("error at APK2");
  let Bx = new Uint8Array(32);
  if(myecc.getXpointFromPubkey(Bx,APK2)) console.log("error at getXpointFromPubkey Bx");
  let hash2 = crypto.createHash('sha256');
  let c_vri = Buffer.from(hash2.update(m+myecc.getModn(Bx)).digest('hex'),'hex');
  c_vri = myecc.getModn(c_vri);
  //console.log(c);
  //console.log(c_vri);
  return c_vri.compare(c);
}

function serialize(u8a){
  return Buffer.from(u8a,'hex').toString('hex');
}
function unserialize(str){
  return new Uint8Array(Buffer.from(str,'hex'));
}


async function main() {
    let DTVotingFC;
    let DTVoting;
    let vn = 3;
    let cvoter = new Array(vn);
    let addr = new Array(vn+1);
    let idList = new Array(vn);
    let pklist = new Array(vn);
    let sklist = new Array(vn);
    let pklists = new Array(vn);
    let sklists = new Array(vn);
    let voterContract = new Array(vn);
    const abi = [
      "function initialize(address iVoter, string calldata iID, string calldata iPK, string calldata iPKs) external",
      "function getIdBasic(address iVoter) external view returns (address,  string memory, string memory, string memory)",
      "function setAnmVote(address iVoter, address isigner, string calldata isi, string calldata ici_pi) external",
      "function getAnmVote(address iVoter, address isigner) external view returns (address,  string memory , string memory)",
      "function signAnmVote(address iVoter, string calldata idsig) external",
      "function getDsigs(address iVoter, address iVerifier) external view returns (address,  string memory)",
      "function openVotesStart(address iyiaddress, string calldata im, string calldata ibm, string calldata ioi, string calldata iyi,string calldata ici) external",
      "function openVotesTermin(bool iFin) external",
      "function getAopenlist(uint index) external view returns (address)",
      "function getAresultCommit(address ianonymous) external view returns (string memory,  string memory, string memory)",
      "function getAresultYi(address ianonymous, address iyiaddress) external view returns (string memory, string memory)"
    ];

    let overrides = {

      // The maximum units of gas for the transaction to use
      gasLimit: 4200000,
  
      // The price (in wei) per unit of gas
      gasPrice:  ethers.utils.parseUnits('5', 'gwei'),

  
    };
    addr = await ethers.getSigners();
    /*
    for(let i =1; i< vn; i++){
      console.log("Account balance:", (await addr[i-1].getBalance()).toString());
      await addr[0].sendTransaction({to: addr[i].address,value: ethers.utils.parseEther("0.2")});
    }
    return;
    */
    DTVotingFC = await ethers.getContractFactory("DTVoting");

    
 
  
    DTVoting = await DTVotingFC.deploy(vn,overrides);
    for(let i=0; i< vn; i++){
      voterContract[i] = await new ethers.Contract(DTVoting.address,abi,addr[i+1]);
    }
    console.log("Account balance:", (await addr[0].getBalance()).toString());

    console.log("Contract address:", DTVoting.address);
    //everyone generate its own keypairs
    privKey = crypto.randomBytes(32);
    for(let i=0; i < vn; i++){
      idList[i] = "voter" + i;
      // generate privKey
      let privKey;
      do {
        privKey = crypto.randomBytes(32);
      } while (myecc.privateKeyVerify(privKey));


      let pubKey  = new Uint8Array(33);
      if(myecc.publicKeyCreate(pubKey,privKey)) console.log("error at publicKeyCreate");

      sklist[i] = privKey;//privateKey;
      pklist[i] = pubKey;//publicKey.export({type:'spki',format:'der'}).toString('hex');


      let privKeys;
      do {
        privKeys = crypto.randomBytes(32);
      } while (myecc.privateKeyVerify(privKeys));


      let pubKeys  = new Uint8Array(33);
      if(myecc.publicKeyCreate(pubKeys,privKeys)) console.log("error at publicKeyCreate s");

      sklists[i] = privKeys;//privateKey;
      pklists[i] = pubKeys;//publicKey.export({type:'spki',format:'der'}).toString('hex');
      
    }


    for(let i=0; i < vn; i++){
      console.log(serialize(pklist[i]));
      console.log(serialize(sklist[i]));
      console.log(serialize(pklists[i]));
      console.log(serialize(sklists[i]));
    }


    let start = Date.now();
    //One man initialize a vote contract
    for(let i=0; i < vn; i++){
      let ins = await DTVoting.initialize(addr[i].address,idList[i],serialize(pklist[i]),serialize(pklists[i]));
    }
    let time = Date.now() - start;
    console.log(`time for initializing a voting contract = ${time} MS`);
    

  }
  
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });


    