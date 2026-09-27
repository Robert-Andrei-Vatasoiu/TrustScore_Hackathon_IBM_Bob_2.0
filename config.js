// config.js — Extension-wide configuration constants.
// Loaded via importScripts() in background.js and directly in content.js.

// Google Safe Browsing Lookup API v4 key. Leave blank to skip Safe Browsing checks.


// Vulnerable library definitions (Sub-Task 9 will flesh these out).
// Each entry: { name, globalVar, versionRegex, maxSafeVersion }
const VULNERABLE_LIBRARIES = [
  // jQuery < 3.5
  {
    name: 'jQuery',
    globalVar: 'jQuery.fn.jquery',
    versionRegex: /jquery[.-](\d+\.\d+(?:\.\d+)?)/i,
    maxSafeVersion: '3.5.0'
  },
  // Angular 1.x (any 1.x version)
  {
    name: 'Angular 1.x',
    globalVar: 'angular.version.full',
    versionRegex: /angular[.-](\d+\.\d+(?:\.\d+)?)/i,
    maxSafeVersion: '1.9999.9999' // flag all 1.x
  },
  // Bootstrap < 4
  {
    name: 'Bootstrap',
    globalVar: null,
    versionRegex: /bootstrap[.-](\d+\.\d+(?:\.\d+)?)/i,
    maxSafeVersion: '4.0.0'
  }
];
