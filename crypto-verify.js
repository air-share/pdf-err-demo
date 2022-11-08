// http://www.java2s.com/ref/javascript/nodejs-crypto-create-signverify-rsasha256.html

// https://stackoverflow.com/questions/53813676/sha256withrsa-signature-verification-in-nodejs-returning-false-every-time
var crypto = require("crypto");
// let fs = require("fs");

const verifyShaRsa = (signature, pubKeyString, signedData) => {
  // https://nodejs.org/api/crypto.html

  console.log(`vvvvsha256WithRSAEncryptionREAL==========`);

  // const algo = "RSA-SHA256";
  const algo = "sha256WithRSAEncryption";

  const verifier = crypto.createVerify(algo);

  verifier.update(signedData);

  var boolResult = verifier.verify(pubKeyString, signature, "binary");

  const res2 = crypto.verify(
    algo,
    signedData,
    pubKeyString,
    // signature
    Buffer.from(signature, "binary")
  );

  console.log({ boolResult, res2 });
  return boolResult;
};

module.exports = verifyShaRsa;

// openssl> x509 -pubkey -in insur.pem -noout -out pubkey.pem
