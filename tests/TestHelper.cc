#include "TestHelper.h"

#include <stdexcept>
#include <boost/filesystem.hpp>

using namespace std;

string TestHelper::ResolvePath(const string& relPath)
{
    namespace fs = boost::filesystem;
    auto baseDir = fs::current_path();

    while (baseDir.has_parent_path())
    {
        auto combinePath = baseDir / relPath;
        if (fs::exists(combinePath))
        {
            return combinePath.string();
        }
        baseDir = baseDir.parent_path();
    }

    throw std::runtime_error("File not found!");
}
