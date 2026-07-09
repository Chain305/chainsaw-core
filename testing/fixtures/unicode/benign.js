// Benign plain-ASCII JavaScript fixture for the hiddenunicode scanner.
// This file must never flag — no suspect code points anywhere.
function greet(name) {
  return "Hello, " + name + "!";
}

module.exports = { greet };
