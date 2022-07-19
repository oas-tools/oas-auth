import { errors, logger } from "oas-devtools/utils";
import { OASBase } from "oas-devtools/middleware";
import { AccessControl } from "accesscontrol";
import jwt from "jsonwebtoken";
import fs from "fs";
import _ from "lodash";
const { ConfigError, AuthError } = errors;

export class OASBearerJWT extends OASBase {
  constructor(oasFile, middleware) {
    super(oasFile, middleware);
  }
  
  /* Initialize auth middleware */
  static initialize(oasFile, config) {
    const secSchemes = oasFile.components.securitySchemes;

    // Create permissions for anonymous default role (read access to any resource with no params)
    const anonymous = {};
    Object.entries(oasFile.paths)
      .filter(([_path, opObj]) => opObj.get && !opObj.get.parameters)
      .forEach(([path, _opObj]) => anonymous[path] = {"read:any": ["*"]});
    
    // Initialize access control
    const accessControls = Object.entries(secSchemes)
      .filter(([_secName, secDef]) => secDef.scheme === "bearer" && secDef.bearerFormat === "JWT")
      .map(([secName, secDef]) => {
        let grantObj = config.acl?.[secName];
        if (typeof grantObj === "string" && fs.existsSync(grantObj)) {
          grantObj = JSON.parse(fs.readFileSync(grantObj));
        }
        grantObj = _.merge(secDef['x-acl-config'], grantObj);

        if (typeof grantObj !== "object" || Object.keys(grantObj).length === 0) {
          throw new ConfigError("Invalid Authentication Config.")
        }

        // Normalize grants object to match express routes
        if (!grantObj.anonymous) grantObj.anonymous = anonymous;
        Object.entries(grantObj).forEach(([role, permissionObj]) => {
          const newPermissionObj = {};
          Object.entries(permissionObj).forEach(([resource, perms]) => {
            let newResourceName = resource.replace(/{/g,':').replace(/}/g, '');
            if (!newResourceName.startsWith('/')) newResourceName = `/${newResourceName}`;
            newPermissionObj[newResourceName] = perms;
          });
          grantObj[role] = newPermissionObj;
        })
        return {[secName]: new AccessControl(grantObj)}
      })[0];

    /* Instanciate middleware */
    return new OASBearerJWT(oasFile, async (req, res, next) => {
      const oasRequest = oasFile.paths[req.route.path][req.method.toLowerCase()];
      if (oasFile.security || oasRequest.security) {
        const secReqs = oasRequest.security ?? oasFile.security;

        /* Logical OR */
        await Promise.any(secReqs
          .filter((secReq) => {
            const secDefs = Object.keys(secReq).map((secName) => secSchemes[secName]);
            return secDefs.some((secDef) => {

              return (
                secDef.type === "http" && req.headers.authorization ||
                secDef.type === "apiKey" && req.query[secDef.name] ||
                secDef.type === "apiKey" && req.headers[secDef.name.toLowerCase()] ||
                secDef.type === "apiKey" && req.headers.cookie?.split(';').find((c) => c.trim().startsWith(`${secDef.name}=`))
              )
            })
          }).map((secReq) => {

          /* Logical AND */
          return Promise.all(Object.keys(secReq).map(async (secName) => {
            const secDef = secSchemes[secName];

            if (secDef.scheme === "bearer" && secDef.bearerFormat === "JWT" && req.headers.authorization) {
              const decoded = res.locals.oas.security?.[secName] ?? jwt.decode(req.headers.authorization.replace(/^Bearer\s/,''));
              
              /* Access control check */
              if (decoded) {
                const ac = accessControls[secName];
                const role = decoded[config.roleBinding] ?? decoded.role ?? "anonymous";
                
                let action, allowed;
                if (req.method === "GET" || req.method === "HEAD") action = "read";
                else if (req.method === "POST") action = "create";
                else if (req.method === "PUT" || req.method === "PATCH") action = "update";
                else if (req.method === "DELETE") action = "delete"
                
                /* Check permissions for each param in request */
                if(res.locals.oas.params && Object.keys(res.locals.oas.params).length > 0) {
                  allowed = Object.entries(res.locals.oas.params).every(([paramName, paramValue]) => {
                    const paramDef = oasRequest.parameters.find((p) => p.name === paramName);
                    const tokenParam = decoded[paramDef['x-acl-binding'] ?? paramName];
                    const ownership = Array.isArray(tokenParam) && tokenParam.includes(paramValue) || tokenParam === paramValue; 
                    let permission = ac.can(role)[`${action}Any`](req.route.path);
                    
                    if (!permission.granted && !tokenParam) logger.warn(`Missing atribute ${paramDef['x-acl-binding'] ?? paramName} in JWT.`);
                    if (!permission.granted && ownership) permission = ac.can(role)[`${action}Own`](req.route.path);

                    return permission.granted;
                  });
                } else {
                  allowed = ac.can(role)[`${action}Any`](req.route.path).granted;
                }

                if (!allowed) {
                  throw new AuthError("Operation not permitted.");
                }

              } else {
                throw new AuthError("Invalid JWT Token");
              }
            }
  
          }));
        })).catch((err) => {
          next(err.errors[0]);
        });
      }
      next();
    });
  }
}
