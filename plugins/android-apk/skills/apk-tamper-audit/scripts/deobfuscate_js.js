#!/usr/bin/env node
'use strict';
/*
 * Usage: node deobfuscate_js.js <suspect-file> <output-dir>
 *
 * Cracked/tampered APKs sometimes bundle a hook script (commonly a Frida
 * gadget's companion script, disguised with a .so extension) that's run
 * `javascript-obfuscator`-style: every string literal is pulled into one
 * big array and only decoded at runtime via a small string-array + RC4
 * decode function. `strings`/grep against a file like this finds nothing
 * useful -- the interesting content simply isn't present as plaintext.
 *
 * This script detects that specific, extremely common obfuscation shape
 * and decodes it -- but it does so by extracting ONLY the array literal,
 * the array-rotation IIFE, and the decode function itself, verifying
 * first that none of those three pieces reference any dangerous global
 * (Frida/Java/process/filesystem/network APIs, `eval`, `Function`,
 * `require`, etc.). It evaluates only that narrow, inert, pure
 * string-math slice inside a bare vm context with zero injected globals.
 * It NEVER executes the file's actual hook/payload logic. If the
 * expected shape isn't found, or if the extracted pieces reference
 * anything beyond pure string/array manipulation, it refuses to decode
 * and says so -- treat that as "this file's obfuscation scheme wasn't
 * automatically verifiable," not as evidence the file is (or isn't) doing
 * anything interesting.
 */
const vm = require('vm');
const fs = require('fs');
const path = require('path');

const DANGEROUS = /\b(Process|Interceptor|Module|Memory|send|recv|Java|ObjC|Socket|NativeFunction|NativePointer|rpc|Thread|WeakRef|hexdump|DebugSymbol|Kernel|File|require|process|child_process|eval|Function|global|globalThis|fs)\b/;

function fail(reason) {
  console.error(`deobfuscate_js.js: ${reason}`);
  process.exit(1);
}

const [, , inputPath, outDir] = process.argv;
if (!inputPath || !outDir) {
  fail('usage: node deobfuscate_js.js <suspect-file> <output-dir>');
}

const src = fs.readFileSync(inputPath, 'utf8');

// 1. Find the string array: `var <name>=[ ... ];`
const arrayMatch = src.match(/var (_?0?x?[a-zA-Z0-9_$]{3,10})=\[/);
if (!arrayMatch) {
  console.log(JSON.stringify({ detected: false, reason: 'no obfuscator.io-style string array found' }, null, 2));
  process.exit(0);
}
const arrayVarName = arrayMatch[1];
const arrayStart = arrayMatch.index;
const arrayEnd = src.indexOf('];', arrayStart) + 2;
if (arrayEnd < 2) fail('found array start but no closing "];"');
const arrayJs = src.slice(arrayStart, arrayEnd);

// 2. Find the decode function: `var <decoderName>=function(<a>,<b>){...}`
//    that indexes into arrayVarName. Search after the array.
const decoderRe = new RegExp(`var (_?0?x?[a-zA-Z0-9_$]{3,10})=function\\([^)]*\\)\\{[^}]*?${arrayVarName}\\[`, 'm');
const decoderMatch = src.slice(arrayEnd).match(decoderRe);
if (!decoderMatch) {
  console.log(JSON.stringify({ detected: 'array-only', reason: 'found string array but no matching decode function -- unusual variant, not auto-decodable' }, null, 2));
  process.exit(0);
}
const decoderVarName = decoderMatch[1];
const decoderRelStart = decoderMatch.index;
const decoderAbsStart = arrayEnd + decoderRelStart;
// Balanced-brace parse to find the end of the decoder function body.
let i = src.indexOf('{', decoderAbsStart);
let depth = 0;
let decoderEnd = -1;
for (; i < src.length; i++) {
  if (src[i] === '{') depth++;
  else if (src[i] === '}') {
    depth--;
    if (depth === 0) { decoderEnd = i + 1; break; }
  }
}
if (decoderEnd === -1) fail('could not balance-parse the decode function body');
const decoderJs = src.slice(decoderAbsStart, decoderEnd);

// 3. The array is typically rotated once via a self-invoking IIFE between
//    the array and the decoder -- grab whatever sits between them too, since
//    decoding is wrong without it.
const rotationJs = src.slice(arrayEnd, decoderAbsStart);

const allPieces = arrayJs + '\n' + rotationJs + '\n' + decoderJs;
if (DANGEROUS.test(allPieces)) {
  console.log(JSON.stringify({
    detected: true,
    decoded: false,
    reason: 'string array + decoder found, but the extracted code references a name outside pure string/array math (Frida/process/fs/etc.) -- refusing to execute it. Treat this file\'s content as unverified, not as clean.',
  }, null, 2));
  process.exit(0);
}

const context = vm.createContext(Object.create(null));
try {
  vm.runInContext(`${allPieces}\nvar __decode = ${decoderVarName};`, context, { timeout: 5000 });
} catch (e) {
  console.log(JSON.stringify({ detected: true, decoded: false, reason: `decoder threw during evaluation: ${e}` }, null, 2));
  process.exit(0);
}
const decode = context.__decode;

// 4. Decode every call site shaped like `IDENT('0xHEX','key')` or
//    `IDENT('0xHEX')` -- local aliases of the decoder all share this
//    call shape regardless of their own name.
const callRe = /_?0?x?[a-zA-Z0-9_$]{3,10}\('(0x[0-9a-fA-F]+)'(?:,\s*'([^']*)')?\)/g;
const seen = new Map();
let m;
while ((m = callRe.exec(src))) {
  const key = m[0];
  if (seen.has(key)) continue;
  try {
    seen.set(key, decode(m[1], m[2] ?? ''));
  } catch (e) {
    // Not every match is really a decoder call (the regex is deliberately
    // loose) -- skip ones that don't decode cleanly.
  }
}

let deobfuscated = src;
for (const [call, decoded] of seen) {
  deobfuscated = deobfuscated.split(call).join(JSON.stringify(decoded));
}

// 5. Reconstruct strings the original code built via `+`-concatenation of
//    multiple literals (common when an obfuscator's string-splitting
//    option is on) -- these are what you actually want to grep for
//    URLs/domains/etc., since any single chunk may be short and innocuous.
const chainRe = /("(?:[^"\\]|\\.)*"\s*\+\s*)+"(?:[^"\\]|\\.)*"/g;
const chains = deobfuscated.match(chainRe) || [];
const reconstructed = new Set();
for (const chain of chains) {
  const lits = chain.match(/"(?:[^"\\]|\\.)*"/g).map((s) => JSON.parse(s));
  const joined = lits.join('');
  if (joined.length > 4) reconstructed.add(joined);
}

fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'deobfuscated_source.js'), deobfuscated);
fs.writeFileSync(path.join(outDir, 'decoded_strings.json'), JSON.stringify([...seen.values()], null, 2));
fs.writeFileSync(path.join(outDir, 'reconstructed_concatenations.json'), JSON.stringify([...reconstructed], null, 2));

console.log(JSON.stringify({
  detected: true,
  decoded: true,
  decoded_literal_count: seen.size,
  reconstructed_concatenation_count: reconstructed.size,
  output_files: [
    path.join(outDir, 'deobfuscated_source.js'),
    path.join(outDir, 'decoded_strings.json'),
    path.join(outDir, 'reconstructed_concatenations.json'),
  ],
}, null, 2));
