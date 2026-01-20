const P = BigInt(
"0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
"E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
);
const G = 2n;

function rand(){
    return BigInt(Math.floor(Math.random() * 1e16));
}

async function hash(msg){
    const buf = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(msg)
    );
    return BigInt("0x" + [...new Uint8Array(buf)]
        .map(x=>x.toString(16).padStart(2,"0")).join(""));
}

function modPow(b,e,m){
    let r=1n;
    while(e>0){
        if(e&1n) r=(r*b)%m;
        b=(b*b)%m;
        e>>=1n;
    }
    return r;
}
