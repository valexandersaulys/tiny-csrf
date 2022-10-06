const { randomBytes, createCipheriv, createDecipheriv } = require("crypto");

const ALGORITHM = "aes-256-cbc";

const encryptCookie = (cookie, _secret) => {
  /**
   * Encrypt a cookie using AES 256 bits
   * @param {cookie} string the cookie we want to encrypt. Will be visible as plain string to client.
   * @param {_secret} string the secret that will be stored server-side. Client will never see this.
   */
  const iv = randomBytes(16);
  const _cipher = createCipheriv(ALGORITHM, Buffer.from(_secret), iv);
  const encrypted = [
    iv.toString("hex"),
    ":",
    _cipher.update(cookie, "utf8", "hex"),
    _cipher.final("hex")
  ];
  return encrypted.join("");
};

const decryptCookie = (cookie, _secret) => {
  /**
   * Decrypt a cookie using AES 256 bits
   * @param {cookie} string the cookie we want to encrypt. Will be visible as plain string to client.
   * @param {_secret} string the secret that will be stored server-side. Client will never see this.
   */
  const _encryptedArray = cookie.split(":");
  if (_encryptedArray.length != 2) throw new Error("bad decrypt");
  const iv = new Buffer(_encryptedArray[0], "hex");
  const encrypted = new Buffer(_encryptedArray[1], "hex");
  const decipher = createDecipheriv(ALGORITHM, _secret, iv);
  const decrypted =
    decipher.update(encrypted, "hex", "utf8") + decipher.final("utf8");
  return decrypted;
};

const verifyCsrf = (requestCsrf, cookieCsrf, _secret) => {
  /**
   * Verify a CSRF token
   * @param {requestCsrf} string the CSRF coming from client side
   * @param {cookieCsrf} string the CSRF as stored in the user's cookies
   * @param {_secret} string the string used to encrypt the CSRF in the first place.
   */
  try {
    const decryptedCookie = decryptCookie(cookieCsrf, _secret);
    return decryptedCookie === requestCsrf;
  } catch (err) {
    return false;
  }
};

module.exports = {
  encryptCookie,
  decryptCookie,
  verifyCsrf
};
