# `tiny-csrf` 

This is a tiny csrf library meant to replace what `csurf` used to do
[before it was deleted](https://github.com/expressjs/csurf). It is
_almost_ a drop-in replacement.  

To install:
```
npm i tiny-csrf
```


To Use:

```
const csurf = require("./middleware/csurf");
const express = require("express");

let app = express();

app.use(
  csurf(
    ["POST"],    // the request methods we want CSRF protection for
    ["/detail", /\/detail\.*/i]  // any URLs we want to exclude either as strings or regexp
  )
);
```

Defaults to only requiring CSRF protection on `POST` requests and
excludes no URLs. 
