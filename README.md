# `tiny-csrf` 

[![Downloads](https://badgen.net/npm/dt/tiny-csrf)](https://www.npmjs.com/package/tiny-csrf)

This is a tiny csrf library meant to replace what `csurf` used to do
[before it was deleted](https://github.com/expressjs/csurf). It is
_almost_ a drop-in replacement.  

**Notice** that if you require very specific security needs you may
want to look elsewhere. This library supports encrypting cookies on
the client side to prevent malicious attackers from looking in but
this may not be sufficient in some cases. For instance, It
does not protect against things such as [double submit 
cookies](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie). Those 
setups require more know-how and involvement. This library aims to
be simple to setup. If you have very strong security needs (e.g. large
scale production application, sensitive information, single page
application that makes many backend requests), then consult [the OWASP
Security Link
here](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
and implement more stringent security. 



## Installation

```
npm i tiny-csrf
```

To Use in your app:

```javascript
const csurf = require("tiny-csrf");
const express = require("express");
const session = require("express-session");

let app = express();

app.use(express.urlencoded({ extended: false })); 
app.use(cookieParser("cookie-parser-secret"));
app.use(session({ secret: "keyboard cat" }));
// order matters: above three must come first
app.use(csurf("123456789iamasecret987654321look"));

// ...declare all your other routes and middleware
```

The secret must be 32 bytes (e.g. 32 characters, 256 bits) in length and uses 
[the built-in `crypto.createCipheriv` library built into Node
](https://nodejs.org/api/crypto.html#cryptocreatecipherivalgorithm-key-iv-options). The
secret length is enforced by the
[`AES-256-CBC`](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
algorithm. 

Defaults to only requiring CSRF protection on `POST`, `PUT`, and `PATCH` requests and
excludes no URLs. The csrf will be checked for in the body of a
request via `_csrf`. 


## Examples

```javascript
const csurf = require("tiny-csrf");
const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");

let app = express();

app.use(express.urlencoded({ extended: false })); 
app.use(cookieParser("cookie-parser-secret"));
app.use(session({ secret: "keyboard cat" }));
// order matters: above three must come first
app.use(
  csurf(
    "123456789iamasecret987654321look", // secret -- must be 32 bits or chars in length
    ["POST"], // the request methods we want CSRF protection for
    ["/detail", /\/detail\.*/i], // any URLs we want to exclude, either as strings or regexp
    [process.env.SITE_URL + "/service-worker.js"]  // any requests from here will not see the token and will not generate a new one
  )
);

app.get("/", (req, res) => {
  const csrfToken = req.csrfToken();
  return res.status(200).send(
    `
<form method="POST" action="/">
  <input name="_csrf" value="${csrfToken}" type="hidden"/>
  <input name="thing" type="text"/>
  <button type="submit"/>Submit</button>
</form>
`.trim()
  );
});

const { randomUUID } = require("crypto");
app.get("/wont-pass", (req, res) => {
  const uuid = randomUUID();
  return res.status(200).send(
    `
<form method="POST" action="/">
  <input name="_csrf" value="${uuid}" type="hidden"/>
  <button type="submit"/>Submit</button>
</form>
`.trim()
  );
});

app.post("/", (req, res) => {
  res.status(200).send("Your cookie passed!");
});

app.listen(3000, () => console.log("running"));
```

## Code Coverage

All contributions must contain [adequeate
testing](https://github.com/valexandersaulys/tiny-csrf/blob/master/test.js). 
```
$ npm run test:coverage

> tiny-csrf@1.1.3 test:coverage
> nyc --reporter=lcov --reporter=text-summary mocha test.js --exit



  Cookie Encryption Tests
    ✔ will encrypt and decrypt a cookie

  Default Options Tests
    ✔ throw internal error if our secret is not long enough
    ✔ throws internal error if we have no cookies
    ✔ generates token for non-POST request
    ✔ allows if the CSRF token is correct
    ✔ does not allow if the CSRF token is incorrect
    ✔ does not allow if the CSRF token is missing in body
    ✔ does not allow if the CSRF token was never generated

  Tests w/Specified Included Request Methods
    ✔ allows if the CSRF token is correct
    ✔ does not allow if the CSRF token is incorrect
    ✔ allows if the method is specified as not included

  Tests w/Specified Excluded URLs
    ✔ allows if the URL is marked as excluded
    ✔ allows if the URL is marked as excluded as a regexp
    ✔ generates a new token if no token is supplied
    ✔ does not allow if the CSRF token is incorrect and the URL is not marked as excluded

  Excluded Referrer Tests (Service Workers)
    ✔ throws error if instantiated without a list as the fourth argument
    ✔ returns null if a service worker accesses an excluded URL
    ✔ returns null if we are a service worker
    ✔ allows for reuse of the CSRF token if there is a service worker request before the real one
    ✔ allows for reuse of the CSRF token if there is a service worker request after the real one

  other tests
    ✔ works #1
    ✔ works #2


  22 passing (75ms)


=============================== Coverage summary ===============================
Statements   : 100% ( 59/59 )
Branches     : 100% ( 30/30 )
Functions    : 100% ( 8/8 )
Lines        : 100% ( 54/54 )
================================================================================
```


## License

[MIT](https://mit-license.org/)


