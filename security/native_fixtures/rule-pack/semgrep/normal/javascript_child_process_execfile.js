// Static toy fixture only; executeFixture is intentionally never invoked.
const child_process = require("child_process");

function executeFixture() {
  return child_process.execFile("fixture-command", []);
}

module.exports = { executeFixture };
