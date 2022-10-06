# `tiny-csrf` 

This is a tiny csrf library meant to replace what `csurf` used to do
[before it was deleted](https://github.com/expressjs/csurf). It is
_almost_ a drop-in replacement.  

Note that if you require very specific security needs you may want to
look elsewhere. This library supports encrypting cookies on the client
side to prevent malicious attackers from looking in. It does not
protect against things such as [double submit
cookies](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie). Those
setups require greater setup and more know-how. This library aims to
be simple to setup. 



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

app.use(
  session({})
);
app.use(
  csurf(
    "123456789iamasecret987654321look",  // secret -- must be 32 bits or chars in length
    ["POST"],    // the request methods we want CSRF protection for
    ["/detail", /\/detail\.*/i]  // any URLs we want to exclude, either as strings or regexp
  )
);

// declare all your other routes and middleware
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

let app = express();

app.use(csurf());

app.get("/", (req, res) => {
  const csrfToken = req.csrfToken(); 
  return res.render("my-template.njk", { csrfToken });
});

/* 
 * then embed the token in a hidden section of a form, e.g.
 * 
 * <form method="POST">
 *   <input name="_csrf" type="hidden" value="{{ csrfToken }}"/>
 *   <button type="submit">Submit</button>
 * </form>
 */

app.post("/", (req, res) => {
  // all invalid or nonexistent CSRF tokens will return 403
  return res.status(200).send("Got it!");
});
```


## License

[MIT](#)
