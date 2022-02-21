// Solidity files have to start with this pragma.
// It will be used by the Solidity compiler to validate its version.
pragma solidity ^0.7.0;

contract DTVoting {
    
    struct User {
        address voter;
        string PK;
        string PKs;
        string ID;
        mapping(address => string)  si;
        mapping(address => string) ci_pi;
        mapping(address => string) dsigs;
    }

     struct Vresult {
        string m;
        string bm;
        string oi;
        mapping(address => string) ci;
        mapping(address => string) yis;
        bool isFinished;
    }

    uint vn;
    address public owner;
    address [] public openlist;
    mapping(address => User) users;
    mapping(address => Vresult) results;

    constructor(uint vnum) {
        vn = vnum;
        owner = msg.sender;
    }

    function initialize(address iVoter, string calldata iID, string calldata iPK, string calldata iPKs) external {
        require(msg.sender == owner && users[iVoter].voter == address(0));
        users[iVoter].voter = iVoter;
        users[iVoter].PK = iPK;
        users[iVoter].PKs = iPKs;
        users[iVoter].ID = iID;
    }

    //be used to check the valid of the Initialization
    function getIdBasic(address iVoter) external view returns (address,  string memory, string memory, string memory){
        return (users[iVoter].voter,users[iVoter].PK,users[iVoter].ID,users[iVoter].PKs);
    }

    //set a anonymous voting value for a voter
    function setAnmVote(address iVoter, address isigner, string calldata isi, string calldata ici_pi) external {
        require(msg.sender == iVoter && bytes(users[iVoter].si[isigner]).length == 0);
        users[iVoter].si[isigner] = isi;
        users[iVoter].ci_pi[isigner] = ici_pi;
    }

    //be used to check the valid of the anonymous voting value
    function getAnmVote(address iVoter, address isigner) external view returns (address,  string memory , string memory){
        return (users[iVoter].voter,users[iVoter].si[isigner],users[iVoter].ci_pi[isigner]);
    }

    //set a signature for the anonymous voting value if it is valid
    function signAnmVote(address iVoter, string calldata idsig) external {
        require(users[iVoter].voter != address(0) && bytes(users[iVoter].dsigs[msg.sender]).length == 0);
        users[iVoter].dsigs[msg.sender] = idsig;
    }

    function getDsigs(address iVoter, address iVerifier) external view returns (address,  string memory){
        return (users[iVoter].voter,users[iVoter].dsigs[iVerifier]);
    }


    
    function openVotesStart(address iyiaddress, string calldata im, string calldata ibm, string calldata ioi, string calldata iyi,string calldata ici) external {
        if(results[msg.sender].isFinished == false){
            
            if(bytes(results[msg.sender].m).length == 0  && bytes(results[msg.sender].bm).length == 0 && bytes(results[msg.sender].oi).length == 0 ){
                results[msg.sender].bm = ibm;  
                results[msg.sender].oi = ioi;
                results[msg.sender].m = im;  
                
            }
            if( bytes(results[msg.sender].ci[iyiaddress]).length == 0 && bytes(results[msg.sender].yis[iyiaddress]).length == 0){
                results[msg.sender].ci[iyiaddress] = ici;
                results[msg.sender].yis[iyiaddress] = iyi;  
            }
              
        }    
    }

    function openVotesTermin(bool iFin) external {
        if(results[msg.sender].isFinished == false){
            openlist.push(msg.sender);
            results[msg.sender].isFinished = iFin;
        }    
    }

    function getAopenlist(uint index) external view returns (address){
        if(index < openlist.length ){
            return openlist[index];
        }else{
            return address(0);
        }
    }



    function getAresultCommit(address ianonymous) external view returns (string memory,  string memory, string memory){
        if(results[ianonymous].isFinished == false){
            return ("","","");
        }else{
            return (results[ianonymous].bm,results[ianonymous].oi,results[ianonymous].m);
        }
    }

    function getAresultYi(address ianonymous, address iyiaddress) external view returns (string memory, string memory){
        if(results[ianonymous].isFinished == false){
            return ("","");
        }else{
            return (results[ianonymous].yis[iyiaddress],results[ianonymous].ci[iyiaddress]);
        }
    }
    

}