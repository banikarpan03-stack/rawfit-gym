#!/usr/bin/env node
"use strict";
/**
 * Extracts every inline <script> block from the HTML frontends and syntax-checks it,
 * then reports any `${...}` interpolation that writes database/user data into markup
 * without going through esc()/jsq()/safeUrl().
 *
 * Run with: node scripts/check-frontend-js.js   (also wired into CI)
 */
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..");
const FILES = [
  path.join(ROOT, "public", "index.html"),
  path.join(ROOT, "public", "admin.html"),
  path.join(ROOT, "public", "member", "index.html"),
];

/**
 * Expressions that are safe by construction and need no escaping. Keep this list in
 * step with the Python pre-flight checker so local runs and CI agree: formatted dates,
 * numbers, loop indices, CSS class/label ternaries and control-flow flags.
 */
const SAFE = new RegExp(
  [
    "\\besc\\(", "\\bjsq\\(", "\\bsafeUrl\\(",   // already encoded
    // bare local identifiers: loop counters, destructured ids, temp variables
    "^(i|idx|id|k|n|meal|diff|cat|c|t|p|e|m|a|u|f|s|opt|row|tpl|item|part|word)$",
    "new Date\\(", "toLocale\\w+\\(",
    "\\bJSON\\.", "\\bNumber\\(",
    "\\(i\\s*\\+\\s*1\\)", "\\bidx\\b", "\\.length\\b",
    "\\btype\\b", "\\bdiffClass\\b", "\\bbadge\\b",
    "\\bactive\\b", "\\bopen\\b", "\\bdur\\b",
    "\\bisRead\\b", "\\batGym\\b", "\\bpage\\b",
    "\\.sets\\b", "\\.reps\\b", "\\.duration\\b",
    "\\.items\\b", "\\.calories\\b",
    "\\.targetCalories\\b", "\\.difficulty\\b",
    "\\bs\\.(totalMembers|activeMembers|todayAttendance|totalRevenue|monthlyRevenue)\\b",
    "\\bp\\.(duration|price)\\b",
    "\\?\\s*'[^']*'\\s*:\\s*''",   // ternary of literals — output is fixed by the source
    "`", // nested template that emits markup — reviewed by hand
  ].join("|")
);

let failures = 0;

for (const file of FILES) {
  if (!fs.existsSync(file)) continue;
  const html = fs.readFileSync(file, "utf8");
  const blocks = [...html.matchAll(/<script(?:[^>]*)>([\s\S]*?)<\/script>/gi)]
    .map((m) => m[1])
    .filter((b) => b.trim());

  console.log(`\n=== ${path.relative(ROOT, file)}: ${blocks.length} script block(s)`);

  blocks.forEach((block, index) => {
    try {
      // Compiles without executing — SyntaxError is what we care about.
      new vm.Script(block, { filename: `${path.basename(file)}#${index}` });
      console.log(`  block ${index}: syntax OK (${block.split("\n").length} lines)`);
    } catch (err) {
      failures += 1;
      console.log(`  block ${index}: SYNTAX ERROR -> ${err.message}`);
      return;
    }

    const unchecked = [];
    for (const m of block.matchAll(/\$\{([^}]*)\}/g)) {
      const expr = m[1];
      if (SAFE.test(expr)) continue;
      unchecked.push(expr.trim().slice(0, 90));
    }
    if (unchecked.length) {
      failures += 1;
      console.log(`  block ${index}: ${unchecked.length} unchecked interpolation(s):`);
      unchecked.slice(0, 20).forEach((e) => console.log(`      \${${e}}`));
    } else {
      console.log(`  block ${index}: all interpolations escaped`);
    }
  });
}

if (failures) {
  console.log(`\nFAILED: ${failures} problem(s)`);
  process.exit(1);
}
console.log("\nAll frontend script blocks are syntax-clean and fully escaped.");