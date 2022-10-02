const { assert, expect } = require("chai");
const { describe, before, beforeEach, after, afterEach, it } = require("mocha");
const sinon = require("sinon");
const { mockRequest, mockResponse } = require("mock-req-res");

const csurf = require("./index");

describe("Default Options Tests", () => {
  before(() => {
    this.csrf = csurf(null, []);
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
      cookies: {},
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
      cookies: {
        csrfToken: "aaaa"
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
      cookies: {
        csrfToken: "aaaabbb"
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
      assert.include(err.message, "Did not get a CSRF token");
    }
    assert.isFalse(next.calledOnce);
  });
  it("does not allow if the CSRF token is missing in body", () => {
    const req = mockRequest({
      method: "POST",
      cookies: {
        csrfToken: "aaaabbb"
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
      assert.include(err.message, "Did not get a CSRF token");
    }
    assert.isFalse(next.calledOnce);
  });
  it("does not allow if the CSRF token was never generated", () => {
    const req = mockRequest({
      method: "POST",
      cookies: {},
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
      assert.include(err.message, "Did not get a CSRF token");
    }
    assert.isFalse(next.calledOnce);
  });
  it("will reuse if the CSRF token already exists in a non-POST", () => {
    const req = mockRequest({
      method: "GET",
      cookies: {
        csrfToken: "aaaabc"
      },
      body: {}
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
      "Did not attach a csrfToken function to req"
    );
    const sampleToken = req.csrfToken();
    assert.equal(sampleToken, "aaaabc");
  });
});

describe("Tests w/Specified Included Request Methods", () => {
  before(() => {
    this.csrf = csurf(["POST", "PUT"], []);
  });

  it("allows if the CSRF token is correct", () => {
    const req = mockRequest({
      method: "PUT",
      cookies: {
        csrfToken: "aaaa"
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
      cookies: {
        csrfToken: "aaaabbb"
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
      assert.include(err.message, "Did not get a CSRF token");
    }
    assert.isFalse(next.calledOnce);
  });
  it("allows if the method is specified as not included", () => {
    const req = mockRequest({
      method: "GET",
      cookies: {
        csrfToken: "aaaa"
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
    this.csrf = csurf(null, ["/detail", /\/detail\.*/i]);
  });

  it("allows if the URL is marked as excluded", () => {
    const req = mockRequest({
      method: "POST",
      cookies: {
        csrfToken: "aaaaa"
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
    const sampleToken = req.csrfToken();
    assert.equal(sampleToken, "aaaaa", "Not reusing csrf tokens");
  });
  it("allows if the URL is marked as excluded as a regexp", () => {
    const req = mockRequest({
      method: "POST",
      cookies: {
        csrfToken: "aaaaa"
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
    const sampleToken = req.csrfToken();
    assert.equal(sampleToken, "aaaaa", "Not reusing csrf tokens");
  });
  it("generates a new token if no token is supplied", () => {
    const req = mockRequest({
      method: "POST",
      cookies: {},
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
      cookies: {
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
      assert.include(err.message, "Did not get a CSRF token");
    }
    assert.isFalse(next.calledOnce);
  });
});
