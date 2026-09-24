#!/usr/bin/env node
import { main } from '../src/cli.js';

main(process.argv.slice(2))
  .then(function (code) {
    process.exitCode = code;
  })
  .catch(function (e) {
    process.stderr.write('fatal: ' + (e && e.stack ? e.stack : e) + '\n');
    process.exitCode = 1;
  });
