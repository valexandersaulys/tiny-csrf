# `tiny-csrf` 

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

The secret must be 32 bits (e.g. characters) in length and uses 
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


## License

[MIT](https://mit-license.org/)
