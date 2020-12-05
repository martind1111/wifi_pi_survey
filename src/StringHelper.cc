/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "StringHelper.h"

using namespace std;

void
StringHelper::ReplaceSubstring(string* const cpstrSource,
                               const string& refcstrSearch,
                               const string& refcstrReplace) {
  string::size_type pos = 0;

  while ((pos = cpstrSource->find(refcstrSearch, pos)) != std::string::npos) {
    cpstrSource->replace(pos, refcstrSearch.length(), refcstrReplace);
    pos += refcstrReplace.length();
  }
}

string
StringHelper::EscapeSpecialCharacters(const string& value) {
  string escaped = value;

  ReplaceSubstring(&escaped, "'", "''");
 
  return escaped;
}

string
StringHelper::EscapeHtml(const string& value) {
  string escaped = value;
  int i;

  ReplaceSubstring(&escaped, "&", "&amp;");

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

