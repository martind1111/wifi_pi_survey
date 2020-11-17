#ifndef _STRING_UTILS_H
#define _STRING_UTILS_H

#include <string>

using namespace std;

string escapeSpecialCharacters(const string& value);
void replaceSubstring(string* const cpstrSource,
                      const string& refcstrSearch,
                      const string& refcstrReplace);

string escapeHtml(const string& value);

#endif // _STRING_UTILS_H
