const { assert, expect } = require("chai");
const { describe, before, beforeEach, after, afterEach, it } = require("mocha");
const sinon = require("sinon");
const { mockRequest, mockResponse } = require("mock-req-res");

const { randomUUID, randomBytes } = require("crypto");
const csurf = require("./index");
const { encryptCookie, decryptCookie, verifyCsrf } = require("./encryption");

describe("Cookie Encryption Tests", () => {
  before(() => {});
  after(() => {});

  it("will encrypt and decrypt a cookie", () => {
    // req.cookies.csrfToken =>  will be scrambled
    const secret = "123456789iamasecret987654321look";
    const csrfToken = randomUUID();
    const encryptedCsrfToken = encryptCookie(csrfToken, secret);
    assert.notEqual(
      csrfToken,
      encryptedCsrfToken,
      "Both are equal as plain string and shouldn't be"
    );
    assert.isTrue(verifyCsrf(csrfToken, encryptedCsrfToken, secret));
    assert.isFalse(
      verifyCsrf(
        csrfToken,
        encryptedCsrfToken,
        randomBytes(16).toString("hex")
      ),
      "Should not be able to verify without the secret"
    );
    assert.isFalse(
      verifyCsrf(randomUUID(), encryptedCsrfToken, secret),
      "Should not verify random UUID tokens"
    );
    assert.isFalse(
      verifyCsrf("", encryptedCsrfToken, secret),
      "Should not verify random blank tokens"
    );
    assert.isFalse(
      verifyCsrf(null, encryptedCsrfToken, secret),
      "Should not verify random null tokens"
    );
  });
});

describe("Default Options Tests", () => {
  before(() => {
    this.secret = "123456789iamasecret987654321look";
    this.csrf = csurf(this.secret);
  });

  it("throw internal error if our secret is not long enough", () => {
    assert.throws(() => csurf("imnotlongenough"));
  });
  it("throws internal error if we have no cookies", () => {
    const req = mockRequest({
      cookies: null
    });
    const res = mockResponse({
      cookie: null
    });
    const next = sinon.stub();
    try {
      this.csrf(req, res, next);
    } catch (err) {
      assert.equal(err.name, "Error", err);
      assert.equal(err.message, "No Cookie middleware is installed");
    }
  });
  it("generates token for non-POST request", () => {
    const req = mockRequest({
      method: "GET",
      signedCookies: {},
      body: {}
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    this.csrf(req, res, next);
    assert.isFunction(req.csrfToken);
    req.csrfToken();
    assert.isTrue(res.cookie.calledOnce);
    assert.equal(res.cookie.getCall(0).args[0], "csrfToken");
    assert.isString(res.cookie.getCall(0).args[1]);
  });
  it("allows if the CSRF token is correct", () => {
    const req = mockRequest({
      method: "POST",
      signedCookies: {
        csrfToken: encryptCookie("aaaa", this.secret)
      },
      body: {
        _csrf: "aaaa"
      }
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    this.csrf(req, res, next);
    assert.isTrue(next.calledOnce);
  });
  it("does not allow if the CSRF token is incorrect", () => {
    const req = mockRequest({
      method: "POST",
      signedCookies: {
        csrfToken: encryptCookie("aaaabbb", this.secret)
      },
      body: {
        _csrf: "aaaa"
      }
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    try {
      this.csrf(req, res, next);
    } catch (err) {
      assert.equal(err.name, "Error");
      assert.include(err.message, "Did not get a valid CSRF token");
    }
    assert.isFalse(next.calledOnce);
  });
  it("does not allow if the CSRF token is missing in body", () => {
    const req = mockRequest({
      method: "POST",
      signedCookies: {
        csrfToken: encryptCookie("aaaabbb", this.secret)
      },
      body: {}
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    try {
      this.csrf(req, res, next);
    } catch (err) {
      assert.equal(err.name, "Error");
      assert.include(err.message, "Did not get a valid CSRF token");
    }
    assert.isFalse(next.calledOnce);
  });
  it("does not allow if the CSRF token was never generated", () => {
    const req = mockRequest({
      method: "POST",
      signedCookies: {},
      body: {}
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    try {
      this.csrf(req, res, next);
    } catch (err) {
      assert.equal(err.name, "Error");
      assert.include(err.message, "Did not get a valid CSRF token");
    }
    assert.isFalse(next.calledOnce);
  });
});

describe("Tests w/Specified Included Request Methods", () => {
  before(() => {
    this.secret = "123456789iamasecret987654321look";
    this.csrf = csurf(this.secret, ["POST", "PUT"], []);
  });

  it("allows if the CSRF token is correct", () => {
    const req = mockRequest({
      method: "PUT",
      signedCookies: {
        csrfToken: encryptCookie("aaaa", this.secret)
      },
      body: {
        _csrf: "aaaa"
      }
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    this.csrf(req, res, next);
    assert.isTrue(next.calledOnce);
  });
  it("does not allow if the CSRF token is incorrect", () => {
    const req = mockRequest({
      method: "PUT",
      signedCookies: {
        csrfToken: encryptCookie("aaaabbb", this.secret)
      },
      body: {
        _csrf: "aaaa"
      }
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    try {
      this.csrf(req, res, next);
    } catch (err) {
      assert.equal(err.name, "Error");
      assert.include(err.message, "Did not get a valid CSRF token");
    }
    assert.isFalse(next.calledOnce);
  });
  it("allows if the method is specified as not included", () => {
    const req = mockRequest({
      method: "GET",
      signedCookies: {
        csrfToken: encryptCookie("aaaa", this.secret)
      },
      body: {
        _csrf: ""
      }
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    this.csrf(req, res, next);
    assert.isTrue(next.calledOnce);
  });
});

describe("Tests w/Specified Excluded URLs", () => {
  before(() => {
    this.secret = "123456789iamasecret987654321look";
    this.csrf = csurf(this.secret, null, ["/detail", /\/detail\.*/i]);
  });

  it("allows if the URL is marked as excluded", () => {
    const req = mockRequest({
      method: "POST",
      signedCookies: {
        csrfToken: encryptCookie("aaaaa", this.secret)
      },
      body: {
        _csrf: ""
      },
      originalUrl: "/detail"
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    this.csrf(req, res, next);
    assert.isTrue(next.calledOnce);
    assert.isFunction(
      req.csrfToken,
      "Did not add the csrfToken to this request"
    );
  });
  it("allows if the URL is marked as excluded as a regexp", () => {
    const req = mockRequest({
      method: "POST",
      signedCookies: {
        csrfToken: encryptCookie("aaaaa", this.secret)
      },
      body: {
        _csrf: ""
      },
      originalUrl: "/detail/603f31d8-9615-40a4-a609-f7bd9059ee6c"
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    this.csrf(req, res, next);
    assert.isTrue(next.calledOnce);
    assert.isFunction(
      req.csrfToken,
      "Did not add the csrfToken to this request"
    );
  });
  it("generates a new token if no token is supplied", () => {
    const req = mockRequest({
      method: "POST",
      signedCookies: {},
      body: {
        _csrf: ""
      },
      originalUrl: "/detail"
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    this.csrf(req, res, next);
    assert.isTrue(next.calledOnce);
    assert.isFunction(
      req.csrfToken,
      "Did not add the csrfToken to this request"
    );
    const sampleToken = req.csrfToken();
    assert.isString(sampleToken);
  });
  it("does not allow if the CSRF token is incorrect and the URL is not marked as excluded", () => {
    const req = mockRequest({
      method: "POST",
      signedCookies: {
        csrfToken: "aaaabbb"
      },
      body: {
        _csrf: "aaaa"
      },
      orignalUrl: "/somethingElse"
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    try {
      this.csrf(req, res, next);
    } catch (err) {
      assert.equal(err.name, "Error");
      assert.include(err.message, "Did not get a valid CSRF token");
    }
    assert.isFalse(next.calledOnce);
  });
});

describe("Excluded Referrer Tests (Service Workers)", () => {
  before(() => {
    this.baseUrl = "http://localhost:3001";
    this.secret = "123456789iamasecret987654321look";
    this.csrf = csurf(
      this.secret,
      null,
      ["/posts"],
      [this.baseUrl + "/service-worker.js"]
    );
  });
  after(() => {});

  it("throws error if instantiated without a list as the fourth argument", () => {
    assert.throws(() =>
      csurf(
        this.secret,
        null,
        ["/posts"],
        "http://localhost:3001/service-worker.js"
      )
    );
  });
  it("returns null if a service worker accesses an excluded URL", () => {
    const req = mockRequest({
      method: "GET",
      signedCookies: {},
      body: {},
      originalUrl: "/posts",
      headers: {
        referer: "http://localhost:3001/service-worker.js"
      }
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    this.csrf(req, res, next);
    assert.isFunction(req.csrfToken);
    const csrfToken = req.csrfToken();
    assert.isNull(csrfToken);
    assert.isFalse(res.cookie.calledOnce);
  });
  it("returns null if we are a service worker", () => {
    const req = mockRequest({
      method: "GET",
      signedCookies: {},
      body: {},
      headers: {
        referer: "http://localhost:3001/service-worker.js"
      }
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    this.csrf(req, res, next);
    assert.isFunction(req.csrfToken);
    const csrfToken = req.csrfToken();
    assert.isNull(csrfToken);
    assert.isFalse(res.cookie.calledOnce);
  });
  it("allows for reuse of the CSRF token if there is a service worker request before the real one", () => {
    const reqOne = mockRequest({
      method: "GET",
      signedCookies: {},
      body: {},
      headers: {
        referer: "http://localhost:3001"
      }
    });
    const resOne = mockResponse({
      cookie: sinon.stub()
    });
    const nextOne = sinon.stub();
    assert.isNotFunction(reqOne.csrfToken);
    this.csrf(reqOne, resOne, nextOne);
    assert.isFunction(reqOne.csrfToken);
    const csrfTokenOne = reqOne.csrfToken();
    assert.isNotNull(csrfTokenOne);

    const req = mockRequest({
      method: "GET",
      signedCookies: {},
      body: {},
      headers: {
        referer: "http://localhost:3001/service-worker.js"
      }
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    this.csrf(req, res, next);
    assert.isFunction(req.csrfToken);
    const csrfToken = req.csrfToken();
    assert.isNull(csrfToken);
    assert.isFalse(res.cookie.calledOnce);

    const reqTwo = mockRequest({
      method: "POST",
      signedCookies: {
        csrfToken: encryptCookie(csrfTokenOne, this.secret)
      },
      body: {
        _csrf: csrfTokenOne
      },
      headers: {
        referer: "http://localhost:3001"
      }
    });
    const resTwo = mockResponse({
      cookie: sinon.stub()
    });
    const nextTwo = sinon.stub();
    assert.isNotFunction(reqTwo.csrfToken);
    this.csrf(reqTwo, resTwo, nextTwo);
    assert.isTrue(nextTwo.calledOnce);
  });
  it("allows for reuse of the CSRF token if there is a service worker request after the real one", () => {
    const req = mockRequest({
      method: "GET",
      signedCookies: {},
      body: {},
      headers: {
        referer: "http://localhost:3001/service-worker.js"
      }
    });
    const res = mockResponse({
      cookie: sinon.stub()
    });
    const next = sinon.stub();
    assert.isNotFunction(req.csrfToken);
    this.csrf(req, res, next);
    assert.isFunction(req.csrfToken);
    const csrfToken = req.csrfToken();
    assert.isNull(csrfToken);
    assert.isFalse(res.cookie.calledOnce);

    const reqOne = mockRequest({
      method: "GET",
      signedCookies: {},
      body: {},
      headers: {
        referer: "http://localhost:3001"
      }
    });
    const resOne = mockResponse({
      cookie: sinon.stub()
    });
    const nextOne = sinon.stub();
    assert.isNotFunction(reqOne.csrfToken);
    this.csrf(reqOne, resOne, nextOne);
    assert.isFunction(reqOne.csrfToken);
    const csrfTokenOne = reqOne.csrfToken();
    assert.isNotNull(csrfTokenOne);

    const reqTwo = mockRequest({
      method: "POST",
      signedCookies: {
        csrfToken: encryptCookie(csrfTokenOne, this.secret)
      },
      body: {
        _csrf: csrfTokenOne
      },
      headers: {
        referer: "http://localhost:3001"
      }
    });
    const resTwo = mockResponse({
      cookie: sinon.stub()
    });
    const nextTwo = sinon.stub();
    assert.isNotFunction(reqTwo.csrfToken);
    this.csrf(reqTwo, resTwo, nextTwo);
    assert.isTrue(nextTwo.calledOnce);
  });
});

describe("other tests", () => {
  /*
   * Informed by real world experience, these are a hodge-podge
   */
  it("works #1", () => {
    assert.isFalse(
      verifyCsrf(
        "f4816018-9ef5-465f-a7f4-970a74a65914",
        "be9877c7edf037cbcbb30ae241485c5d:de116ba2a276c9d1fc53822a994e4d0b5c97485d3e4f52d13a8b9f19e0604932d2eedd393b9237d010570dd2410ec474",
        "HHRfgzuBeTcN8ZKB"
      )
    );
  });
  it("works #2", () => {
    assert.isFalse(
      verifyCsrf(
        "4f1a27bb-2d92-4ce9-9b36-b1e098d0c34e",
        "0abfde14f7f07fd170bc26bdd695ccd8:0d4abf106e48dad61779bd8d8e9cc8bebdb8edcffc5003a8848d248ac2c6fcb94a6bad7db19e0152d3fed04069a843a5",
        "HHRfgzuBeTcN8ZKB"
      )
    );
  });
});
