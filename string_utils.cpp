#include "string_utils.h"

using namespace std;

void
replaceSubstring(string* const cpstrSource,
                 const string& refcstrSearch,
                 const string& refcstrReplace) {
  string::size_type pos = 0;

  while ((pos = cpstrSource->find(refcstrSearch, pos)) != std::string::npos) {
    cpstrSource->replace(pos, refcstrSearch.length(), refcstrReplace);
    pos += refcstrReplace.length();
  }
}

string
escapeSpecialCharacters(const string& value) {
  string escaped = value;

  replaceSubstring(&escaped, "'", "''");
 
  return escaped;
}

string
escapeHtml(const string& value) {
  string escaped = value;
  int i;

  replaceSubstring(&escaped, "&", "&amp;");

  // Replace all control characters with '^' followed by a letter. For instance,
  // CTRL-A (ASCII code 1) becomes "^A".
  char replaceStr[2];
  replaceStr[0] = '^';
  for (i = escaped.length() - 1; i >= 0; i--) {
    if (escaped[i] <= 26) {
      replaceStr[1] = 'A' + escaped[i] - 1;
      escaped.replace(i, 1, replaceStr, 0, 2);
    }
    if (escaped[i] == 0x1c) {
      replaceStr[1] = '\\' + escaped[i] - 1;
      escaped.replace(i, 1, replaceStr, 0, 2);
    }
    if (escaped[i] == 0x1b) {
      replaceStr[1] = '[' + escaped[i] - 1;
      escaped.replace(i, 1, replaceStr, 0, 2);
    }
    if (escaped[i] == 0x1d) {
      replaceStr[1] = ']' + escaped[i] - 1;
      escaped.replace(i, 1, replaceStr, 0, 2);
    }
  }

  return escaped;
}

