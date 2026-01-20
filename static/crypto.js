// static/crypto.js
const P = BigInt(
  "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
  "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
);
const G = 2n;

function rand() {
  const arr = new Uint32Array(4);
  crypto.getRandomValues(arr);
  let r = 0n;
  for (let i = 0; i < arr.length; i++) {
    r = (r << 32n) + BigInt(arr[i]);
  }
  return r % (P - 1n);
}

async function H(...args) {
  const msg = args.map(String).join('');
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(msg));
  return BigInt("0x" + Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join(''));
}

function modPow(base, exp, mod) {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}