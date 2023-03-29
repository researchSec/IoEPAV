const ChainsqlAPI = require('chainsql');
const chainsql = new ChainsqlAPI();
const crypto  = require('crypto');
const secp256k1 = require('secp256k1');
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

async function start() {

  let vn = 20;
  await chainsql.connect("ws:");
  let cvoter = new Array(vn);
  let idList = new Array(vn);
  let pklist = new Array(vn);
  let sklist = new Array(vn);
  let pklists = new Array(vn);
  let sklists = new Array(vn);
  const users = [
  {
    secret: "pwkpNabzRpiVVyoySFPYkE9tngvcokG3BFuEHXpv8hzz9JDbiZN",
    address: "znZq1NAg2qqHsFR6ymdE8pjKH7hKouVcUy",
    publicKey: "pYvGmm3LY8XGTEKNQYAxgFtACTaGWrB56bkhAEZ5sQpt6McPxq8p9n3b3B6Xhrcn1WVNN2BzuRUMiV3WbyAcUibvasd79CCQ"
  },
  {
    secret: "p9KVpT7s9Nen8zrE9ewvDT6XfA5Gq2zFnJToinSmJxxAaZiR1EV",
    address: "zKTVpwifYoNVSbKAgo4RB8WuKmSkoBQ3kQ",
    publicKey: "pYvEWveWAPgyG6MW9sgCC3y9HGg1JzqbLh7aZ22X4jNvcDQK7tFZ4NjQumoKxFqJjNLX9mgwsPHino7JW54zfrAbaF7hMvjy"
  },
  {
    secret: 'pwjuoFKmJxNBNhE9JD9QUhM1y1CuhujhepXPCVMpgB4XX9Cmgm7',
    address: 'zBuJrwhcgkRySBuFPDFQpncvAbgoPBpiZp',
    publicKey: 'pYvUQ42fnuGhYJoH5yR2rsjbbz6JSCxax2CugtAaBKzv9YCLtrEYo14gGPYioqgtMUj47iqLd5NJ9EdRQe8U6fQqyLPVeLHv'
  },
  {
    secret: 'pw6qoHoCZ1HTiCRZSX3RJAfkXc1Ko9ktQCZzjKT31H2udzw5QAC',
    address: 'zJ9gJNLrczh8JRi2evPTWrXJZcjxdZUBn8',
    publicKey: 'pYvpNMcNxxi7W1JcGpYyRAhiAp9AwdG6VqaWPQPvhE6HGkf4CzkpddvCWdK1mJ1e8mic16AVsHmvngSbpSKpzDURm3hQ7TNM'
  },
  {
    secret: 'pwocX7DL8GqFf8XwiW1AMneRQKTWAvX28wAeoKrJbooZszrLW7V',
    address: 'zwDQ3WwEuCNfzhVWMiymMHu23PtK6uciVa',
    publicKey: 'pYusnZCpzGeT8uiSSS5cahVTVDVYLESdUYa6WMt65RfeVGH5pr1dYw216drxxRhtCov3ZtijAep2dvU8n3Y9fQM7ECESBik7'
  },
  {
    secret: 'p9bTSKhfg3egR899VcgEYXEgzuCeyLPu93bBffnsN5C1KeJHrg8',
    address: 'zMFpoc1h8i6qkeMyWXqSXcpNZr8wwaeGEb',
    publicKey: 'pYvc4PJdPSmp3Vmyf75HxCsXNUDTDyN2epKXrb2UEcGborEkqXe6d73vzFNQNXBet5Wv8WpptShQKzw3Wi5qNjgMTo3XVdqq'
  },
  {
    secret: 'pwAgh8sTy9EaMSEbVtkw53cQnfZMB3QU5LCAkPuYiyuvGdZbmQy',
    address: 'z9Y2xn8gsDsGiN3BfmgYeH15jcPeYq1bxQ',
    publicKey: 'pYvx9WPbQdiWDbgDvbGdBZmjC5rJ8K2mdugx1u6ewbchPdPFrWGTQqXCCfjAW8DjxwLakk5qgaMWaWNSsGTDCYjPHydqdG79'
  },
  {
    secret: 'p9d4hvZZLhWmZ2Vg5LMPRSdEw3nnmgsqdDLZcJ73YEeiv5TmDcT',
    address: 'zwFaNGa3AJ3dfue8GEFeWZ3AjAQBypMB1Z',
    publicKey: 'pYvKkwDN7YbCJfNk9xzdq5NkCP7HV4NNnZEmfYPwzrfmi1Jy7x1doQHpyRTi237pfaaQMj99kSuFqXLMmAjCANRdR9JSzoso'
  },
  {
    secret: 'pwQppRpTohWXRGtjXdqEmYryCWmi24FuS8Qkt4Lkmj7Pu2fGurD',
    address: 'zJhBn3hHGUYgBvXWrgKLKemvgmqaYykQHc',
    publicKey: 'pYvLB3tvQsGQr9fivkCtcVG66Yxnw767i4eQFibfXnsb97B4sVFWi32xo6zprw995sEGeR7qXU6MTrknwsbhSCjRGJPbvP9f'
  },
  {
    secret: 'p9LU3c9SqQ7BoL9Dkun9dPVRdkQahNDSKtRMwx52SKfo2mpvLs9',
    address: 'zHibVreS9H4Vxf1sTX1Q1pqpZaWaTwNaDj',
    publicKey: 'pYvpz9Y8EhgKL24sASyQQVFswUMkAWtXPo179WGyvi3YMercj8E2gArc2VQ1Q2bYJRVcAkwA5VY21uzwnYrpq3SSRxVVidaH'
  },
  {
    secret: 'pwzuuSRCDnE9ToyKB3ZKQ3Zo3jEriNLFL8ncDqi27wCSUffUs5j',
    address: 'zJTX1VscHW82Xgm3Aq2mMCaYJaxzijW2MD',
    publicKey: 'pYvwSfvzirMzbcVs5fz2YQ3Gd7XdzaxDT7iTDtw9ChTSUR2wKN5ApKUwtTDBYXPK31Mr16t5zKCiANWRmU3DvV6ZkLExrqQy'
  },
  {
    secret: 'pwhZ662dwPkSPtQc5xCpFgubfzk8X8PKxbzxXhJeWM37xdrZzp8',
    address: 'z4W3suUrKJ8uDasxGbx8HwNpJVd3yACQSF',
    publicKey: 'pYvRRotEJfUww3AotqzEPaaUmHGvpTbcaA8aUYFLhtoVNL5FtcC3DAxuruvHDBEvpFk7MGm4FbNPv6XSkXj4Y5nBgy92fx4a'
  },
  {
    secret: 'p9Ba6J8qd7TYSxVtPiad559rkpRFkGAYgiqaWYuyQ1NxaikUpg6',
    address: 'zPwyraqUmzUJcTsJoBQ93YhbEiCFKfmdJx',
    publicKey: 'pYvE3kUX8grkhT3JLkdKG54Nko3CDmMXXPrN8dDjaknLebTobsQ2VoozPXp6oTJLrA8Nn751BpkcWXdoKfYdxdixF3HVQfFq'
  },
  {
    secret: 'pBzD13wH9ErWYKgDFif99QCXQD4Y9jhPUVAbJs688idsL6S3GZj',
    address: 'zKTPPwoE72MR8EeeJAdwEaZwHwbRaoS5xo',
    publicKey: 'pYv4qiG7GgdkRj91GWWWFE8Lw1p7xaLtx59QhfKB6qTH3xKfS3FifN5Q4juFprKCKc3tDon5EtTvFAnrcs43XL4Ku413KNZQ'
  },
  {
    secret: 'pwg3pAV9sx79f7BKvMmb4KpHFxdm2RAJNRsXS1Xm9M6TgRbjePF',
    address: 'zJyw2bNCrJwyw5UThdYSPFffuMriWHMSsP',
    publicKey: 'pYvNd2Fp8NA8gobCmCxb8DTX73gYtmpU77TBuUiYRoFGToqSkvurV5FsR18Vk8viMqDXM9jaEyK1CQ4VfTwnvwFf2eqp5Dqj'
  },
  {
    secret: 'p9XGnefcvEpsuzEPMt5tgta5XQMSC3i2KQ5HPj4cGAb9q2WtQaS',
    address: 'zB98LyRXifNpCeVBpA982zsqm6WRfcpv36',
    publicKey: 'pYvESdB98TnezADGoCrouqCzqt6ayVmh83xHJ1zG3MR7qXhcoPA7gcaU4ukhWiiSkNYEWc684AjjrUA51YCzu3p4mSBy7ja8'
  },
  {
    secret: 'p9qcu1tBL4GfYgGgPgWMfG8ci3u7CucsbdLkpcMRxBsyE15dDmZ',
    address: 'zntpvhs72odVigJY4iM34bgSTYJt5vjSxz',
    publicKey: 'pYvM2cu899iJRK38ULMmCAN42NTwcAMvND4e8WeGSmzgogAyYnt6HcghSoWMpaetrY8Sdz9vapCbUuaTdyR41tfTei18dma6'
  },
  {
    secret: 'pw92hApDjt73GWEvCSZwoF89AJf4mwd9gp72qwCnudk2kEvJzW7',
    address: 'zPcstaawyovoUgPoLoTXGrRsrWghTyPhqk',
    publicKey: 'pYvf7SzqscNgm8TCRuez27jbz8GJTH55qzeK35hma7D13Fn428ky3QfeDC7vGjH24wS4F2VTLbaTdEDx7jhMBUPCi8X2HSyZ'
  },
  {
    secret: 'p92zXYSY1k5fAwzK5GFnC6yFxsyFbyQPYEBSqX1JuTy7Vy2GTE5',
    address: 'zGNBNuXgYX4YbusXq3L11tL4NGm1m4WnCa',
    publicKey: 'pYvBLmR39BhD9Li1bK9xGqqZ48C1UVobBLjtqB6DkqypP8cQMrKCKxwhFvy7Vd8pAi1SYPrgzC2VTKBbBEkbzmoSeP9ERUP7'
  },
  {
    secret: 'p9bWU39we1L9c1DaeqWAtET4Z7mCQRzD5XbFQrJiieDh4djy15u',
    address: 'zfmrE29V1rncuRCP14wAX3vo3ntaHE9WYp',
    publicKey: 'pYvWRme86UVyqS9LmEuVgczbVyzbPChxcc8csxxJGxGGnAfjarq7pe9yZZKdtWXYWsnfaXD7i7jTSRBvxqU4wMsCkwyGwWv9'
  }
  ];

  await chainsql.as(users[0]);

  

   //load the deployed contract and call a function

  const abi = '[{	"inputs": [	{"internalType": "uint256","name": "vnum","type": "uint256"}],"stateMutability": "nonpayable","type": "constructor"},{"inputs": [{"internalType": "address","name": "iVoter","type": "address"},{"internalType": "address","name": "isigner","type": "address"}],"name": "getAnmVote","outputs": [{"internalType": "address","name": "","type": "address"},{"internalType": "string","name": "","type": "string"},{"internalType": "string","name": "","type": "string"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "uint256","name": "index","type": "uint256"}],"name": "getAopenlist","outputs": [{"internalType": "address","name": "","type": "address"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "address","name": "ianonymous","type": "address"}],"name": "getAresultCommit","outputs": [{"internalType": "string","name": "","type": "string"},{"internalType": "string","name": "","type": "string"},{"internalType": "string","name": "","type": "string"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "address","name": "ianonymous","type": "address"},{"internalType": "address","name": "iyiaddress","type": "address"}],"name": "getAresultYi","outputs": [{"internalType": "string","name": "","type": "string"},{"internalType": "string","name": "","type": "string"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "address","name": "iVoter","type": "address"},{"internalType": "address","name": "iVerifier","type": "address"}],"name": "getDsigs","outputs": [{"internalType": "address","name": "","type": "address"},{"internalType": "string","name": "","type": "string"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "address","name": "iVoter","type": "address"}],"name": "getIdBasic","outputs": [{"internalType": "address","name": "","type": "address"},{"internalType": "string","name": "","type": "string"},{"internalType": "string","name": "","type": "string"},{"internalType": "string","name": "","type": "string"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "address","name": "iVoter","type": "address"},{"internalType": "string","name": "iID","type": "string"},{"internalType": "string","name": "iPK","type": "string"},{"internalType": "string","name": "iPKs","type": "string"}],"name": "initialize","outputs": [],"stateMutability": "nonpayable","type": "function"},{"inputs": [{"internalType": "address","name": "iyiaddress","type": "address"},{"internalType": "string","name": "im","type": "string"},{"internalType": "string","name": "ibm","type": "string"},{"internalType": "string","name": "ioi","type": "string"},{"internalType": "string","name": "iyi","type": "string"},{"internalType": "string","name": "ici","type": "string"}],"name": "openVotesStart","outputs": [],"stateMutability": "nonpayable","type": "function"},{"inputs": [{"internalType": "bool","name": "iFin","type": "bool"}],"name": "openVotesTermin","outputs": [],"stateMutability": "nonpayable","type": "function"},{"inputs": [{"internalType": "uint256","name": "","type": "uint256"}],"name": "openlist","outputs": [{"internalType": "address","name": "","type": "address"}],"stateMutability": "view","type": "function"},{"inputs": [],"name": "owner","outputs": [{"internalType": "address","name": "","type": "address"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "address","name": "iVoter","type": "address"},{"internalType": "address","name": "isigner","type": "address"},{"internalType": "string","name": "isi","type": "string"},{"internalType": "string","name": "ici_pi","type": "string"}],"name": "setAnmVote","outputs": [],"stateMutability": "nonpayable","type": "function"},{"inputs": [{"internalType": "address","name": "iVoter","type": "address"},{"internalType": "string","name": "idsig","type": "string"}],"name": "signAnmVote","outputs": [],"stateMutability": "nonpayable","type": "function"}]';
  const contractObj = chainsql.contract(JSON.parse(abi),"zfPBVVZsqwSXoSxgpEjbLsRQxfmt6xhKvV");


  //everyone generate its own keypairs
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

  let testcast = [3,5,10,15,20];

  //-----------The initialization stage-------------------
  let begin = Date.now();
  let timecost;
  for(let i=0; i < vn; i++){
    let ins = await contractObj.methods.initialize(users[i].address,idList[i],serialize(pklist[i]),serialize(pklists[i])).submit({
      Gas: 500000,
      expect: "validate_success"
    }).then(res => {
        console.log(res);
    }).catch(err => {
        console.log(err);
    });
    if(i == 2){
      timecost = Date.now() - begin;
      console.log(`testcast=3 time for initializing a voting contract = ${timecost} MS`);
    }else if(i ==4){
      timecost = Date.now() - begin;
      console.log(`testcast=5 time for initializing a voting contract = ${timecost} MS`);
    }else if(i ==9){
      timecost = Date.now() - begin;
      console.log(`testcast=10 time for initializing a voting contract = ${timecost} MS`);
    }else if(i ==14){
      timecost = Date.now() - begin;
      console.log(`testcast=15 time for initializing a voting contract = ${timecost} MS`);
    }else if(i ==19){
      timecost = Date.now() - begin;
      console.log(`testcast=20 time for initializing a voting contract = ${timecost} MS`);
    }
  }

  for(let k=0; k < 5; k++){
      
      //------------------The BindX stage--------------------
      begin = Date.now();

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
      console.log("commit_c:"+commit_c);
      console.log("commit_o:"+serialize(commit_o));
      let voterindex = k;
        
      //blind the commit_c
      for(let i =0; i < testcast[k]; i++){
        if(i == voterindex) continue;
        let cc = requester_gen_blind_c(unserialize(commit_c),pklists[i],pklist[i],gamaG,elta);
        cvoter[i] = cc.c;
        let datai = serialize(cc.cpi) + idList[voterindex];       
        // sign the message
        let mhash = crypto.createHash('sha256');
        let dataihash = mhash.update(datai);
        dataihash = dataihash.digest('hex');
        const sigObj = secp256k1.ecdsaSign(unserialize(dataihash), sklist[voterindex]);
        await chainsql.as(users[voterindex]);
        let ins = await contractObj.methods.setAnmVote(users[voterindex].address,users[i].address,serialize(sigObj.signature),serialize(cc.cpi)).submit({
          Gas: 500000,
          expect: "validate_success"
        }).then(res => {
            console.log(res);
        }).catch(err => {
            console.log(err);
        });
      }

      timecost = Date.now() - begin;
      console.log(`testcast=${testcast[k]} time for blindX = ${timecost} MS`);

      
      //---------------The BindS stage-----------------------
      begin = Date.now();
      for(let i =0; i < testcast[k]; i++){
        if(i == voterindex) continue;
        await chainsql.as(users[i]);
        let ins = await contractObj.methods.getAnmVote(users[voterindex].address,users[i].address).call();
        let voter = ins[0];
        let si = ins[1];
        let cpi = ins[2];
        if(voter !== users[voterindex].address) {console.log("error voter");return;}
        let vdatai = cpi + idList[voterindex];
        let vmhash = crypto.createHash('sha256');
        let vdataihash = vmhash.update(vdatai);
        vdataihash = vdataihash.digest('hex');
        if(secp256k1.ecdsaVerify(unserialize(si), unserialize(vdataihash), pklist[voterindex])){
          let dsi = signer_gen_blind_s(sklists[i],sklist[i],unserialize(cpi));
          let sins = await contractObj.methods.signAnmVote(users[voterindex].address,serialize(dsi)).submit({
            Gas: 500000,
            expect: "validate_success"
          }).then(res => {
              console.log(res);
          }).catch(err => {
              console.log(err);
          });
        }
      }
      timecost = Date.now() - begin;
      console.log(`testcast=${testcast[k]}  time for blindS = ${timecost} MS`);


      //---------------The open stage-----------------------
      begin = Date.now();
      await chainsql.as(users[voterindex]);
      for(let i =0; i < testcast[k]; i++){
        if(i == voterindex) continue;
        let ins = await contractObj.methods.getDsigs(users[voterindex].address,users[i].address).call();
        let voter = ins[0];
        let dsi = ins[1];
        if(voter !== users[voterindex].address) {console.log("error voter");return;}
        let yi = requester_gen_s_for_c(unserialize(dsi),gama);

        if(!verify_blind_signature(unserialize(commit_c),cvoter[i],pklist[i],yi)) {

          let oins = await contractObj.methods.openVotesStart(users[i].address,m,commit_c,serialize(commit_o),serialize(yi),serialize(cvoter[i])).submit({
            Gas: 500000,
            expect: "validate_success"
          }).then(res => {
              console.log(res);
          }).catch(err => {
              console.log(err);
          });
        }
      }

      let oins = await contractObj.methods.openVotesTermin(true).submit({
        Gas: 500000,
        expect: "validate_success"
      }).then(res => {
          console.log(res);
      }).catch(err => {
          console.log(err);
      });
      timecost = Date.now() - begin;
      console.log(`testcast=${testcast[k]} time for open a voting commitment = ${timecost} MS`);


      //---------------The verifying stage-----------------------
      begin = Date.now();
      let anonymous = await contractObj.methods.getAopenlist(voterindex).call();
      let count = 0;
      let valid = 0;
      let ins1 = await contractObj.methods.getAresultCommit(anonymous).call();
      for(let i =0; i < testcast[k]; i++){
        if(i == voterindex) continue;
        let ins2 = await contractObj.methods.getAresultYi(anonymous, users[i].address).call();
        //console.log(ins2[1]);
        if(!verify_blind_signature(unserialize(ins1[0]),unserialize(ins2[1]),pklist[i],unserialize(ins2[0]))){
          count = count + 1;
        }
        if(count*2 > testcast[k]) {
          valid = 1;
          break;
        }
      }
      if(valid){
        let fhash = crypto.createHash('sha256');
        console.log("commit_o:"+ins1[1]);
        console.log("M:"+ins1[2]);
        let veri_commit_c = fhash.update(ins1[2]+ins1[1]);
        veri_commit_c = veri_commit_c.digest('hex');
        if(veri_commit_c == ins1[0]) {
          console.log(ins1[2]);  
        }
      }
      timecost = Date.now() - begin;
      console.log(`testcast=${testcast[k]} time for verifying a voting commitment = ${timecost} MS`);
  }
  
 
}
start();




