#ifndef MAP_EXTRA_H_INCLUDED
#define MAP_EXTRA_H_INCLUDED

#include <string>
#include <map>
#include <string.h>

struct strICaseComp
{
    // case-independent (ci) compare_less binary function
    struct nocase_compare
    {
        bool operator() (const unsigned char& c1, const unsigned char& c2) const {
            return tolower (c1) < tolower (c2);
        }
    };
    bool operator() (const std::string & s1, const std::string & s2) const {
        return std::lexicographical_compare
                (s1.begin (), s1.end (),   // source range
                 s2.begin (), s2.end (),   // dest range
                 nocase_compare ());  // comparison
    }
};

using string_icase_map = std::map<std::string, std::string, strICaseComp>;

#endif // MAP_EXTRA_H_INCLUDED
