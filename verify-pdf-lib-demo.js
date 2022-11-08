const fs = require("fs");

/* npm i --force @ninja-labs/verify-pdf */
const verifyPDF = require("@ninja-labs/verify-pdf");

const pdfPath = `change-me.pdf`;

console.log('pdfPath:', pdfPath);

const buf = fs.readFileSync(pdfPath);
console.log(verifyPDF(buf));

/* 
Expect something like
{
  verified: false,
  authenticity: true,
  integrity: true,
  expired: true,
  signatures: [
    {
      verified: false,
      authenticity: true,
      integrity: true,
      expired: true,
      meta: [Object]
    }
  ]
}

*/
