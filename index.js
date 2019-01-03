const openpgp = require('openpgp');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

openpgp.config.aead_protect = true;
const user = {
    name: "test",
    email: "test@gmail.com",
    passphrase: "123123"
};

const encryptedFolder = path.join(__dirname, "encrypted");
const decryptedFolder = path.join(__dirname, "/../test/decrypted/");

const image = path.join(__dirname, "test.csv");
const txt = path.join(__dirname, "test.txt");

function CryptoService(user) {
  if (!user) {
      throw new Error();
  }
  if (!user.passphrase) {
      user.passphrase = crypto.randomBytes(32).toString('hex');
  }
  this.user = user;
}

CryptoService.prototype.generateKeys = function () {
  const options = {
      userIds: [{name: this.user.name, email: this.user.email}],
      numBits: 1024,
      passphrase: this.user.passphrase
  };
  return openpgp.generateKey(options);
};

CryptoService.prototype.encrypt = async function (data) {
  const options = {
      publicKeys: (await openpgp.key.readArmored(this.user.publicKey)).keys,
      message: openpgp.message.fromBinary(data),
      armor: false
  };
  return openpgp.encrypt(options);
};

CryptoService.prototype.decrypt = async function (data) {
  let privKeyObj = (await openpgp.key.readArmored(this.user.privateKey)).keys[0];
  privKeyObj.decrypt(this.user.passphrase);
  const options = {
    message: (await openpgp.message.read(data)), // parse armored message
    publicKeys: (await openpgp.key.readArmored(this.user.publicKey)).keys, // for verification (optional)
    privateKeys: [privKeyObj]   // parse armored message
  };
  return openpgp.decrypt(options);
};

console.time('test');
const service = new CryptoService(user);
user.privateKey = fs.readFileSync("Ben - private.asc")
user.publicKey = fs.readFileSync("Ben.asc");

const readFile = fs.readFileSync(image);
service.encrypt(readFile)
    .then(function (cipherText) {
        fs.writeFileSync("encryptedData.csv.pgp", cipherText.message.packets.write());
        const encryptedFile = fs.readFileSync("encryptedData.csv.pgp");
        service.decrypt(encryptedFile)
            .then(function (binary) {
                fs.writeFileSync("decryptedData.csv", binary.data)
                console.timeEnd("test")
            });
    })
    .catch(function (err) {
        console.log(err);
    })
