import { errors } from "oas-devtools/utils";
import jwt from 'jsonwebtoken';

const { SecurityError, ConfigError } = errors;

export function bearerJwt(config) {
  
  // Init checks
  if (typeof config !== 'object') { 
    throw new ConfigError("Invalid security config");
  }
  if (['issuer', 'secret'].some(k => !Object.keys(config).includes(k))) {
    throw new ConfigError(`Missing ${['issuer', 'secret'].filter(k => !Object.keys(config).includes(k))} in security config`);
  }

  /* Validate function for OASSecurity middleware */
  return function securityHandler(token) {
    const regex = /^Bearer\s/;
    if (regex.test(token)) {
      const newToken = token.replace(regex, '');
      return jwt.verify(newToken, config.secret, { algorithms: config.algorithms ?? ['HS256'], issuer: config.issuer});
    } else {
      throw new SecurityError("Invalid token provided");
    }
  }
}

/* CONFIG OBJ

  issuer-------> JWT issuer
  secret-------> JWT Secret
  algorithms---> List of algorithms

*/