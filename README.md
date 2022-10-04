# `tiny-csrf` 

This is a tiny csrf library meant to replace what `csurf` used to do
[before it was deleted](https://github.com/expressjs/csurf). It is
_almost_ a drop-in replacement.  



## Installation

```
npm i tiny-csrf
```

To Use in your app:

```javascript
const csurf = require("tiny-csrf");
const express = require("express");

let app = express();

app.use(
  csurf(
    ["POST"],    // the request methods we want CSRF protection for
    ["/detail", /\/detail\.*/i]  // any URLs we want to exclude, either as strings or regexp
  )
);

// declare all your other routes and middleware
```

Defaults to only requiring CSRF protection on `POST` requests and
excludes no URLs. 

This uses the built-in [`crypto`
library](https://nodejs.org/api/crypto.html#cryptorandomuuidoptions)
for generating CSRF tokens. This may or may not be sufficient for your
needs. 


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
