# OAS Auth

<div align="center">

[![NPM](https://nodei.co/npm/@oas-tools/auth.png?compact=true)](https://nodei.co/npm/@oas-tools/auth)

![npm](https://img.shields.io/npm/v/@oas-tools/auth)
![node-current](https://img.shields.io/node/v/@oas-tools/auth)
![npm](https://img.shields.io/npm/dw/@oas-tools/auth)
[![Node.js CI](https://github.com/oas-tools/oas-tools/actions/workflows/nodejs.yaml/badge.svg)](https://github.com/oas-tools/oas-auth/actions/workflows/nodejs.yaml)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-green.svg)](https://conventionalcommits.org)
<br/>

[![Known Vulnerabilities](https://snyk.io/test/github/oas-tools/oas-auth/main/badge.svg)](https://snyk.io/test/github/oas-tools/oas-auth)
[![Coverage Status](https://coveralls.io/repos/github/oas-tools/oas-auth/badge.svg?branch=main)](https://coveralls.io/github/oas-tools/oas-auth?branch=main)
</div>

## Contents
- [OAS Auth](#oas-auth-1)
- [JWT Bearer Token](#jwt-bearer-token)
  * [Security Handler](#security-handler)
  * [Authentication Middleware](#authentication-middleware)
- [Compatibility chart](#compatibility-chart)

## OAS Auth
OAS Auth is an npm package that groups a series of handlers and middleware functions that can be integrated inside [OAS Tools Core Library](https://github.com/oas-tools/oas-tools) in order to perform different kinds of validation towards security and authentication. Some of the contents in this package may not be compatible with older versions of NodeJS, please check the [compatibility chart](#compatibility-chart) at the end of this document.

## JWT Bearer Token

### Security Handler
The security handler function extends OAS-Security native middleware in order to verify the token provided through the `Authorization` header in request. This function must be included in OAS-Tools options object for OAS-Security to be able to use it.

#### usage
> Take into account that security middleware must be enabled through config `cfg.middleware.security.disable = false` and `secSchemeName` must match the name specified for that security scheme in the OpenAPI document.

```javascript
import { bearerJwt } from 'oas-auth/handlers';

var options_object = {
    middleware: {
      security: {
        auth: {
          secSchemeName: bearerJwt({issuer: 'issuerName', secret: 'secretKey'})
        }
      }
    }
  };

oasTools.initialize(app, options_object).then(() => ...)
```

#### config
The handler function takes three possible arguments:

|          	 | **Type**            |**Required**    |**Description**                         |
|------------|:-------------------:|:--------------:|----------------------------------------|
| `issuer`   | `String` or `Array` |**✓**           | Valid values for the `iss` field       |
| `secret` 	 | `String` or `Buffer`|**✓**           | Secret used to sign the token          |
| `algoritms`| `Array`             |✘               | Allowed algorithms, default `["HS256"]`|

#### errors
Upon JWT token verification, the following errors may be throwed and could be handled through a custom handling function specified in the OAS-Tools configuration under `middleware.error.customHandler`.

- **JsonWebTokenError**: Verification failed due to some error concerning JWT. Check the [possible messages](https://github.com/auth0/node-jsonwebtoken#jsonwebtokenerror).
- **SecurityError**: The token provided does not match `Bearer <token>` structure. Handled automatically by the native error handler to respond `401 Unauthorized`.

### Authentication Middleware
The `OASBearerJWT` authentication middleware is an external resource that can be included inside the OAS-Tools Core Library through the `use` function. This middleware will be registered inside the express chain in order to check access permissions for the API operations.

> For this middleware to work, you first need to declare a security scheme in the OpenAPI document with type `http`, scheme `bearer` and bearer format `JWT`. See [OpenAPI docs](https://swagger.io/docs/specification/authentication/bearer-authentication/) on how to use Bearer Authentication.

```javascript
import { OASBearerJWT } from 'oas-auth/middleware';

const authCfg= {acl: { secSchemeName:'route/to/permissions.json' }}

oasTools.use(OASBearerJWT, authCfg, 2);
oasTools.initialize(app, options_object).then(() => ...)

```

#### config
The configuration object can be provided through the `use` function like shown in the example above, or through the OpenAPI document, under `components.securitySchemes.[schemeName].x-acl-config`. See [setting permission](#setting-permission) section below. Available configuration options are listed in the following table.

|          	 			 | **Type**            |**Description**                             		 |
|------------------------|:-------------------:|-----------------------------------------------------|
|`roleBinding`			 | `String`            | Binds `role` to another attribute of the JWT		 |
| `acl`      			 | `Object`            | Access control configuration      	        		 |
| `acl.[schemeName]` 	 | `Object` or `String`| Permission declaration. Can be object or a file path|
| `checkOwnership`    | `Function`           | Function that checks wether some resource is owned or not by the client |


#### setting permission
Permissions are declared upon middleware initialization, they can be set through `config.acl` or through `x-acl-config` field inside security schemes in the OpenAPI document. The structure of the JSON object used by the middleware to declare those authentication rules is the one used by [Access Control](https://github.com/onury/accesscontrol#defining-all-grants-at-once) since `OASBearerJWT` relies in that library under the hood.

The following snippet shows how permissions are declared inside the OpenAPI Document.

```yaml
...
securitySchemes:
    bearerjwt:
      type: http
      scheme: bearer
      bearerFormat: JWT
      x-acl-config:
        user:
          example/endpoint/{parameter}:
            "read:own":
              - "*"
```

Similarly, the declaration above can be translated into a JS object or written to a JSON file and then included inside the ACL configuration for the middleware.

```javascript
//JS object
const authCfg = {
  acl: {
    bearerjwt: {
      user: {
        example/endpoint/{parameter}: { "read:own" : ["*"] }
      }
    }
  } 
}
```
In both cases we are defining a role `user` that have access to `example/endpoint/{parameter}`when that resource is owned by him. That means the JWT payload must contain an attribute `role` (or an attribute with the same name specified in `config.roleBinding`) and an attribute `parameter` so the middleware can validate if that user owns that resource.

The `parameter` attribute in the JWT payload can be a single value or a list of allowed values. This way, if the JWT payload contains `{role: user, parameter: [1,3,5]}` the following requests will be handled has follows:
- `GET /example/endpoint/1` returns `200 OK`
- `GET /example/endpoint/3` returns `200 OK`
- `GET /example/endpoint/4` returns `403 Forbidden`
- `GET /example/endpoint/271` returns `403 Forbidden`

> Bear in mind that `parameter` is influenced by [serialization rules](https://swagger.io/docs/specification/serialization/) and must be expressed according to that.

If the JWT payload contains a different attribute for `parameter`, you may bind `parameter`to that attribute, using `x-acl-binding` when declaring `parameter` in the OpenAPI document.

```yaml
...
parameters:
  - name: parameter
    required: true
    in: path
    schema:
      type: integer
    x-acl-binding: JWTParamAttribute
...
```

Finally, in case no `role` is specified in the JWT payload, the middleware will assume an `anonymous` role that only has read access to those operations that doesn't include parameters of any type. This role can be overriden by configuration.

#### Checking ownership
The middleware can be configured to check wether a resource is owned by the client or not. This is done by providing a function that receives the JWT payload and the parameters name and value, to retur a boolean value. The function must be provided through `config.checkOwnership`

```javascript
    authCfg.checkOwnership = async (decoded, paramName, paramValue) => {
      return await Actor.findOne({ [paramName]: paramValue }).then(actor => actor?.email === decoded?.email);
    }
```

> **NOTE**: Bear in mind that the function MUST return a boolean value. Promises are suported, but you will need to wait for them to resolve by using `await` or `.then()`. If you don't return a boolean value, the middleware will assume that the resource is not owned by the client and will return `403 Forbidden`.

## Compatibility chart
The following chart shows which versions of NodeJS are compatible with each of the contents inside this package.

<table>
	<tr>
    	<th>NodeJS compatibility</th>
        <th>≤ v12</th>
        <th>v14</th>
        <th>v16</th>
        <th>v18</th>
    </tr>
    <tr>
    	<td>BearerJWT Handler</td>
        <td align="center">✘</td>
        <td align="center"><b>✓</b></td>
        <td align="center"><b>✓</b></td>
        <td align="center"><b>✓</b></td>
    </tr>
    <tr>
    	<td>BearerJWT Middleware</td>
        <td align="center">✘</td>
        <td align="center">✘</td>
        <td align="center"><b>✓</b></td>
        <td align="center"><b>✓</b></td>
    </tr>
</table>
