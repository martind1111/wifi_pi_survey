#ifndef _STRING_HELPER_H
#define _STRING_HELPER_H

#include <string>

using namespace std;

class StringHelper {
public:
    static string escapeSpecialCharacters(const string& value);
    static void replaceSubstring(string* const cpstrSource,
                                 const string& refcstrSearch,
                                 const string& refcstrReplace);

    string escapeHtml(const string& value);
};

#endif // _STRING_HELPER_H
