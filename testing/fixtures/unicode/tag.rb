# Tag-character fixture — includes U+E0041 (TAG LATIN CAPITAL LETTER A)
# inside a comment. Tag characters render as nothing in most editors but
# carry a payload that can be extracted with a simple scan of the file.
# Hidden tag:󠁁
module Example
  HIDDEN = true
end
