#ifndef _FILESYSTEM_IO_FILEHANDLER_H_
#define _FILESYSTEM_IO_FILEHANDLER_H_

#include "datatypes_uri.h"

#include <string>
#include <map>
#include <utility>

std::map<int, Uri> readRawDB(const std::string& filename);

std::map<int, Uri> readAuthDB(const std::string& dataFile, const std::string& passPhrase);

std::pair<std::string,std::string> readIvAndChallenge(const std::string& dataFile);

bool updateDatafile(std::map<int, Uri> uriMap,const std::string& dataFile);

bool statDataFile(const std::string& dataFile);

std::pair<bool, std::string> findDataFile();

#endif
