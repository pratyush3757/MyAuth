#ifndef _FILESYSTEM_IO_H_
#define _FILESYSTEM_IO_H_

#include "datatypes_uri.h"

#include <string>
#include <map>
#include <utility>

std::map<int, Uri> readAuthDB(const std::string& filename);
std::map<int, Uri> readAuthDB(const std::string& filename, const std::string& passPhrase);
bool statDataFile(const std::string& dataFile);
std::pair<bool, std::string> findDataFile();

Uri parseUri(const std::string& uri);

std::string deriveUriString(const Uri inputUri);

#endif
