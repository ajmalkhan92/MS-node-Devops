
// Mock the jsonwebtoken module
jest.mock('jsonwebtoken');

const jwt = require('jsonwebtoken');
const authenticateJWT = require('../src/middileware/authMiddleware');

// Mock request and response objects
const mockReq = (headers = {}) => ({
  headers,
});

const mockRes = () => {
  const res = {};
  res.sendStatus = jest.fn().mockReturnValue(res);
  return res;
};

describe('authenticateJWT middleware', () => {

  it('should send 401 Unauthorized if no token is provided', () => {
    const req = mockReq();
    const res = mockRes();
    const next = jest.fn();

    authenticateJWT(req, res, next);

    expect(jwt.verify).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
    expect(res.sendStatus).toHaveBeenCalledWith(401);
    expect(req.user).toBeUndefined();
  });

  it('should call next() if a valid JWT token is provided with correct issuer and id', () => {
    const VALID_JWT_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJpc3N1ZXIiOiJ1c2VycmVhZG9ubHkiLCJpZCI6IjEifQ.I-4ZrJVlPCosO-ShePbiesqsOnFH4mxG7R6hI6fSLMg"
    const req = mockReq({
      authorization: 'Bearer '+VALID_JWT_TOKEN,
    });
    const res = mockRes();
    const next = jest.fn();

    const decodedToken = {
      issuer: 'userreadonly',
      id: '1',
    };

    jwt.verify.mockReturnValue(decodedToken);

    authenticateJWT(req, res, next);

    expect(jwt.verify).toHaveBeenCalledWith(VALID_JWT_TOKEN, 'test');
    expect(next).toHaveBeenCalled();
    expect(res.sendStatus).not.toHaveBeenCalled();
    expect(req.user).toEqual(decodedToken);
  });

  it('should send 403 Forbidden if token has invalid issuer or id', () => {
    const INVALID_ISSUER_TOKEN = 'eyJhbGciOiJIUzI1NiJ9.eyJpc3N1ZXIiOiJkc2ZzZCIsImlkIjoiMSJ9.3I0c2woz3VXBfYitRwSyiLLutTlB7CHVWjNxNea-IRU'
    const req = mockReq({
      authorization: 'Bearer '+INVALID_ISSUER_TOKEN,
    });
    const res = mockRes();
    const next = jest.fn();

    const decodedToken = {
      "issuer": "dsfsd", //invalid issuer
      "id": "1" 
    }

    jwt.verify.mockReturnValue(decodedToken);

    authenticateJWT(req, res, next);

    expect(jwt.verify).toHaveBeenCalledWith(INVALID_ISSUER_TOKEN, 'test');
    expect(next).not.toHaveBeenCalled();
    expect(res.sendStatus).toHaveBeenCalledWith(403);
    expect(req.user).toBeUndefined();
  });

  it('should send 401 Forbidden if token is invalid', () => {
    const TOKEN_WITH_INVALID_SECRET = 'eyJhbGciOiJIUzI1NiJ9.eyJpc3N1ZXIiOiJkc2ZzZCIsImlkIjoiMSJ9.uqPwez7WQ9F20UbNYS51PQNT1m5LQTS64horlFAansc'
    const req = mockReq({
      authorization: 'Bearer '+TOKEN_WITH_INVALID_SECRET,
    });
    const res = mockRes();
    const next = jest.fn();

    jwt.verify.mockImplementation(() => {
      throw new Error();
    });

    authenticateJWT(req, res, next);

    expect(jwt.verify).toHaveBeenCalledWith(TOKEN_WITH_INVALID_SECRET, 'test');
    expect(next).not.toHaveBeenCalled();
    expect(res.sendStatus).toHaveBeenCalledWith(401);
    expect(req.user).toBeUndefined();
  });

});
