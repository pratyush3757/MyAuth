#ifndef _IMPORT_EXPORT_H_
#define _IMPORT_EXPORT_H_

#include "datatypes_uri.h"

#include <string>
#include <map>

bool convertToDatafile(const std::string& clearFile,
                       const std::string& dataFile,
                       const std::string& passPhrase);

bool exportRawData(std::map<int,Uri> uriMap, const std::string& exportfile);

#endif
