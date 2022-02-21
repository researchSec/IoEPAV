// We import Chai to use its asserting functions here.
const { expect } = require("chai");
const crypto  = require('crypto');
const { copyFileSync } = require("fs");
//const BigNumber = require('bignumber.js');
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
  return c_vri.compare(c);
}

function serialize(u8a){
  return Buffer.from(u8a,'hex').toString('hex');
}
function unserialize(str){
  return new Uint8Array(Buffer.from(str,'hex'));
}



describe("DTVoting", function () {

  
  let DTVotingFC;
  let DTVoting;
  let vn = 50;
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
    "function openVotesT(bool iFin) external",
    "function getAopenlist(uint index) external view returns (address)",
    "function getAresultCommit(address ianonymous) external view returns (string memory,  string memory, string memory)",
    "function getAresultYi(address ianonymous, address iyiaddress) external view returns (string memory, string memory)"
  ];

  before(async function () {

    DTVotingFC = await ethers.getContractFactory("DTVoting");
    addr = await ethers.getSigners();
    DTVoting = await DTVotingFC.deploy(vn);
    //console.log(DTVoting.address);
    for(let i=0; i< vn; i++){
      voterContract[i] = await new ethers.Contract(DTVoting.address,abi,addr[i+1]);
    }
    
  });

  describe("Function Tests", function () {
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

    let start = Date.now();
    let gama,elta;
    do {
      gama = crypto.randomBytes(32);
    } while (myecc.privateKeyVerify(gama));
    let gamaG  = new Uint8Array(33);
    if(myecc.publicKeyCreate(gamaG,gama)) console.log("error at publicKeyCreate");
    do {
      elta = crypto.randomBytes(32);
    } while (myecc.privateKeyVerify(elta));
    const commit_o = crypto.randomBytes(32);
    let m = "candidate1";
    let hash = crypto.createHash('sha256');
    let commit_c = hash.update(m+serialize(commit_o));
    commit_c = commit_c.digest('hex');
    let time = Date.now() - start;
    console.log(`time for generating  a commitment = ${time} MS`);

    it("Should initialize a voting contract correctly", async function () {
      


      start = Date.now();
      for(let i=0; i < vn; i++){
        let ins = await DTVoting.initialize(addr[i+1].address,idList[i],serialize(pklist[i]),serialize(pklists[i]));
      }
      time = Date.now() - start;
      console.log(`time for initializing a voting = ${time} MS`);
      start = Date.now();
      //verify the valid of the initialization
      for(let i=0; i < vn; i++){
        let ins = await voterContract[0].getIdBasic(addr[i+1].address);
        if( addr[i+1].address != ins[0]||serialize(pklist[i]) != ins[1] || idList[i] != ins[2] || serialize(pklists[i]) != ins[3]){
          console.log("invalid initialization");
          break;
        }
      }
      time = Date.now() - start;
      console.log(`time for verifying the initialization of a voting = ${time} MS`);

    });


    it("set a anonymous voting value for a voter", async function () {

      let tstart = Date.now();
      //blind the commit_c
      for(let i =1; i < vn; i++){
        if(1 == i){
          start = Date.now();
        }
        let cc = requester_gen_blind_c(unserialize(commit_c),pklists[i],pklist[i],gamaG,elta);
        cvoter[i] = cc.c;
        let datai = serialize(cc.cpi) + idList[0];       
        // sign the message
        let mhash = crypto.createHash('sha256');
        let dataihash = mhash.update(datai);
        dataihash = dataihash.digest('hex');
        const sigObj = secp256k1.ecdsaSign(unserialize(dataihash), sklist[0]);//
        let ins = await voterContract[0].setAnmVote(addr[1].address,addr[i+1].address,serialize(sigObj.signature),serialize(cc.cpi));
        if(1 == i){
          time = Date.now() - start;
          console.log(`time for blinding a commitment = ${time} MS`);
        }
      }
      let ttime = Date.now() - tstart;
      console.log(`time for blinding the voting value = ${ttime} MS`);
    });

    it("set a disig for a blind voting value ", async function () {
      let tstart = Date.now();
      for(let i =1; i < vn; i++){
        //console.log(secp256k1.ecdsaVerify(sigObj.signature, unserialize(dataihash), pklist[0]));//
        if(1 == i){
          start = Date.now();
        }
        let ins   = await voterContract[i].getAnmVote(addr[1].address,addr[i+1].address);
        let voter = ins[0];
        let si = ins[1];
        let cpi = ins[2];
        if(voter !== addr[1].address) console.log("error voter");
        let vdatai = cpi + idList[0];
        let vmhash = crypto.createHash('sha256');
        let vdataihash = vmhash.update(vdatai);
        vdataihash = vdataihash.digest('hex');
        if(secp256k1.ecdsaVerify(unserialize(si), unserialize(vdataihash), pklist[0])){
          if(1 == i){
            time = Date.now() - start;
            console.log(`time for verifying a blind commitment = ${time} MS`);
          }
          if(1 == i){
            start = Date.now();
          }
          let dsi = signer_gen_blind_s(sklists[i],sklist[i],unserialize(cpi));
          let sins = await voterContract[i].signAnmVote(addr[1].address,serialize(dsi));
          if(1 == i){
            time = Date.now() - start;
            console.log(`time for generatig a blind signature = ${time} MS`);
          }
        }
      }

      let ttime = Date.now() - tstart;
      console.log(`time for generatig blind signatures for all voters = ${ttime} MS`);
    });


    
      it("open a blind voting value ", async function () {
      let tstart = Date.now();
      for(let i =1; i < vn; i++){
        if(1 == i){
          start = Date.now();
        }
        let ins = await DTVoting.getDsigs(addr[1].address,addr[i+1].address);
        let voter = ins[0];
        let dsi = ins[1];
        if(voter !== addr[1].address) console.log("error voter");
        let yi = requester_gen_s_for_c(unserialize(dsi),gama);
        if(1 == i){
          time = Date.now() - start;
          console.log(`time for generating a signature = ${time} MS`);
        }
        if(1 == i){
          start = Date.now();
        }
        if(!verify_blind_signature(unserialize(commit_c),cvoter[i],pklist[i],yi)) {
          if(1 == i){
            time = Date.now() - start;
            console.log(`time for verifying a blind signature = ${time} MS`);
          }
          await DTVoting.openVotesStart(addr[i+1].address,m,commit_c,serialize(commit_o),serialize(yi),serialize(cvoter[i]));
        }
      }
 
      await DTVoting.openVotesTermin(true);
      let ttime = Date.now() - tstart;
      console.log(`time for Opening voting values = ${ttime} MS`);
    });


    it("open a  voting value ", async function () {
      let tstart = Date.now();
      let anonymous = await DTVoting.getAopenlist(0);
      let count = 0;
      let valid = 0;
      let ins1 = await DTVoting.getAresultCommit(anonymous);
      for(let i =1; i < vn; i++){
        let ins2 = await DTVoting.getAresultYi(anonymous, addr[i+1].address);
        if(count*2 > vn) {
          valid = 1;
          break;
        }
        if(!verify_blind_signature(unserialize(ins1[0]),unserialize(ins2[1]),pklist[i],unserialize(ins2[0]))){
          count = count + 1;
        }
    
      }
      let ttime = Date.now() - tstart;
      console.log(`time for verifying voting signatures = ${ttime} MS`);
      tstart = Date.now();
      if(valid){
        let fhash = crypto.createHash('sha256');
        let veri_commit_c = fhash.update(ins1[2]+ins1[1]);
        veri_commit_c = veri_commit_c.digest('hex');
        if(veri_commit_c == ins1[0]) {
          console.log(ins1[2]);  
        }
    
      }
      ttime = Date.now() - tstart;
      console.log(`time for calculating a original voting = ${ttime} MS`);
 
    });






  });
});