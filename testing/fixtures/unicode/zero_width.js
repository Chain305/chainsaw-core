// Zero-width fixture — embeds U+200B (zero-width space) inside an identifier
// so the name visually reads "adminCheck" but is a different symbol than any
// legitimate "adminCheck" elsewhere in the codebase.
function admin​Check(user) { // there is a U+200B between "admin" and "Check"
  return user.role === "admin";
}

module.exports = { adminCheck: admin​Check };
