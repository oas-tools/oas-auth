'use strict';

import express from 'express';
import http from 'http';
import fs from 'fs';

var server;
var app = express();

// Only for testing
let defaults = JSON.parse(fs.readFileSync('tests/testServer/.oastoolsrc'));
let {use, initialize} = await importFresh('../../node_modules/oas-tools/src/index.js');

export {use};
export async function init(config) {
  app.use(express.json({limit: '50mb'}));
  app.get('/status', (_req, res, _next) => res.status(200).send('Up'));
  await initialize(app, config ?? defaults).then(() => {
    server = http.createServer(app)
    server.listen(8080);
  });
}

export function close() {
  app = express();
  server.close();
  clearCache(); // Clears module cache
  process.removeAllListeners(); // prevents memory leak
}

async function clearCache() {
  let mod = await importFresh('../../node_modules/oas-tools/src/index.js');
  initialize = mod.initialize;
  use = mod.use;
}

async function importFresh(modulePath) {
  const cacheBustingModulePath = `${modulePath}?update=${Date.now()}`
  return (await import(cacheBustingModulePath))
}