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
