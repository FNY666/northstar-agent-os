// Static toy fixture only; executeFixture is intentionally never invoked.
const child_process = require("child_process");

function executeFixture(command) {
  return child_process.exec(command);
}

module.exports = { executeFixture };
