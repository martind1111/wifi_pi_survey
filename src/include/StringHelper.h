#ifndef _STRING_HELPER_H
#define _STRING_HELPER_H

#include <string>

class StringHelper {
public:
    static std::string EscapeSpecialCharacters(const std::string& value);
    static void ReplaceSubstring(std::string* const cpstrSource,
                                 const std::string& refcstrSearch,
                                 const std::string& refcstrReplace);

    static std::string EscapeHtml(const std::string& value);
};

#endif // _STRING_HELPER_H
