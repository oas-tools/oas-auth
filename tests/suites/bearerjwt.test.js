import {init, use, close} from '../testServer/index.js';
import { bearerJwt } from '../../handlers/index.js';
import { OASBearerJWT } from '../../middleware/index.js';
import fs from 'fs';
import assert from 'assert';
import axios from 'axios';
import jwt from "jsonwebtoken";
import sinon from "sinon";

export default () => {

    describe('\n   - BearerJWT Tests', () => {
        describe('Security Handler Initialization', () => {
            let cfg;
            beforeEach(async () => {
                cfg = JSON.parse(fs.readFileSync('tests/testServer/.oastoolsrc'));
                cfg.logger.level = "off";
                cfg.middleware.security.auth = {
                    alwaysSuccess: () => {}, // Do nothing
                    bearerjwt: bearerJwt({issuer: 'testIssuer', secret: 'testSecret'})
                };
            });

            it ('Should throw Config Error when handler config is not an object', async () => {
                try {
                    cfg.middleware.security.auth.bearerJwt = bearerJwt('not an object');
                    await init(cfg);
                } catch (err) {
                    assert.equal(err.name, 'ConfigError');
                    assert.equal(err.message, 'Invalid security config');
                }
            });

            it ('Should throw Config Error when missing issuer and secret in handler config', async () => {
                try {
                    cfg.middleware.security.auth.bearerJwt = bearerJwt({});
                    await init(cfg);
                } catch (err) {
                    assert.equal(err.name, 'ConfigError')
                    assert.equal(err.message, 'Missing issuer,secret in security config');
                }
            });
        });

        describe('Security Handler Function', () => {
            before(async () => {
                let cfg = JSON.parse(fs.readFileSync('tests/testServer/.oastoolsrc'));
                cfg.logger.level = "off";
                cfg.middleware.security.auth = {
                    alwaysSuccess: () => {}, // Do nothing
                    bearerjwt: bearerJwt({issuer: 'testIssuer', secret: 'testSecret'})
                };
                cfg.middleware.error.customHandler = (err, send) => {
                    if(err.name === "JsonWebTokenError") send(403);
                };
                await init(cfg);
            });
    
            after(() => {
                close();
            });
        
            it('Should verify token correctly and return 200 OK', async () => {
                let token = jwt.sign({payload: 'test'}, 'testSecret', {issuer: 'testIssuer'})
                await axios.get('http://localhost:8080/api/v1/bearerjwt', {
                    headers: {'Authorization': `Bearer ${token}`}
                }).then(res => {
                    assert.equal(res.status, 200);
                    assert.deepStrictEqual(res.data.security?.bearerjwt, jwt.decode(token));
                });
            });

            it('Should fail when invalid token provided', async () => {
                let token = jwt.sign({payload: 'test'}, 'testSecret', {issuer: 'testIssuer'})
                await axios.get('http://localhost:8080/api/v1/bearerjwt', {
                    headers: {'Authorization': `${token}`}
                })
                .then(() => assert.fail("Expected code 401 but got 2XX"))
                .catch(err => {
                    assert.equal(err.response.status, 401);
                    assert.equal(err.response.data?.error, 'SecurityError: Invalid token provided');
                });
            });

            it('Should fail when malformed jwt token provided', async () => {
                let token = "malformed token";
                await axios.get('http://localhost:8080/api/v1/bearerjwt', {
                    headers: {'Authorization': `Bearer ${token}`}
                })
                .then(() => assert.fail("Expected code 403 but got 2XX"))
                .catch(err => {
                    assert.equal(err.response.status, 403);
                    assert.equal(err.response.data?.error, 'JsonWebTokenError: jwt malformed');
                });
            });          
        });

        describe('Auth Middleware Initialization', () => {
            let cfg;
            beforeEach(async () => {
                cfg = JSON.parse(fs.readFileSync('tests/testServer/.oastoolsrc'));
                cfg.logger.level = "off";
                cfg.middleware.security.auth = {
                    alwaysSuccess: () => {}, // Do nothing
                    bearerjwt: bearerJwt({issuer: 'testIssuer', secret: 'testSecret'})
                };
            });

            afterEach(() => {
                close();
            });

            it ('Should throw Config Error when no config provided', async () => {
                sinon.stub(process, "exit");
                use(OASBearerJWT, {}, 2);
                await init(cfg);

                assert(process.exit.calledWith(1));
                process.exit.restore();
            });
        });

        describe('Auth Middleware Initialization', () => {
            before(async () => {
                let cfg = JSON.parse(fs.readFileSync('tests/testServer/.oastoolsrc'));
                cfg.logger.level = "off";
                cfg.middleware.security.auth = {
                    alwaysSuccess: () => {}, // Do nothing
                    bearerjwt: bearerJwt({issuer: 'testIssuer', secret: 'testSecret'})
                };
                use(OASBearerJWT, { acl: {bearerjwt: 'tests/testServer/permissions/bearerjwt.json'}}, 2);
                await init(cfg);
            });

            after(() => {
                close();
            }); 

            it('Should assume "anonymous" permissions when no role in jwt and return 200 OK', async () => {
                let token = jwt.sign({test: 'norole'}, 'testSecret', {issuer: 'testIssuer'})
                await axios.get('http://localhost:8080/api/v1/bearerjwt', {
                    headers: {'Authorization': `Bearer ${token}`}
                }).then(res => {
                    assert.equal(res.status, 200);
                    assert.deepStrictEqual(res.data.security?.bearerjwt, jwt.decode(token));
                });
            });

            it('Should assume "anonymous" permissions when no role in jwt and return 403 when params needed', async () => {
                let token = jwt.sign({paramBinding: 1}, 'testSecret', {issuer: 'testIssuer'})
                await axios.get('http://localhost:8080/api/v1/bearerjwt/1', {
                    headers: {'Authorization': `Bearer ${token}`}
                })
                .then(() => assert.fail("Expected code 403 but got 2XX"))
                .catch(err => {
                    assert.equal(err.response.status, 403);
                    assert.equal(err.response.data.error, "AuthError: Operation not permitted.");
                });
            });

            it('Should verify "user" permissions and return 200 OK', async () => {
                let token = jwt.sign({role: 'user'}, 'testSecret', {issuer: 'testIssuer'})
                await axios.get('http://localhost:8080/api/v1/bearerjwt', {
                    headers: {'Authorization': `Bearer ${token}`}
                }).then(res => {
                    assert.equal(res.status, 200);
                    assert.deepStrictEqual(res.data.security?.bearerjwt, jwt.decode(token));
                });
            });

            it('Should verify "user" permissions and return 200 OK when provided params correctly (list)', async () => {
                let token = jwt.sign({role: 'user', paramBinding: [1,2,3]}, 'testSecret', {issuer: 'testIssuer'})
                await axios.get('http://localhost:8080/api/v1/bearerjwt/2', {
                    headers: {'Authorization': `Bearer ${token}`}
                }).then(res => {
                    assert.equal(res.status, 200);
                    assert.deepStrictEqual(res.data.security?.bearerjwt, jwt.decode(token));
                });
            });

            it('Should verify "user" permissions and return 200 OK when provided params correctly (single param)', async () => {
                let token = jwt.sign({role: 'user', paramBinding: 3}, 'testSecret', {issuer: 'testIssuer'})
                await axios.get('http://localhost:8080/api/v1/bearerjwt/3', {
                    headers: {'Authorization': `Bearer ${token}`}
                }).then(res => {
                    assert.equal(res.status, 200);
                    assert.deepStrictEqual(res.data.security?.bearerjwt, jwt.decode(token));
                });
            });

            it('Should verify "user" permissions and return 403 token does not give permission to the operation', async () => {
                let token = jwt.sign({role: 'user', paramBinding: [1,2,3]}, 'testSecret', {issuer: 'testIssuer'})
                await axios.get('http://localhost:8080/api/v1/bearerjwt/5', {
                    headers: {'Authorization': `Bearer ${token}`}
                })
                .then(() => assert.fail("Expected code 403 but got 2XX"))
                .catch(err => {
                    assert.equal(err.response.status, 403);
                    assert.equal(err.response.data.error, "AuthError: Operation not permitted.");
                });
            });
        });
    })
}