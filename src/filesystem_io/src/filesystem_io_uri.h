#ifndef _FILESYSTEM_IO_UI_H_
#define _FILESYSTEM_IO_UI_H_

#include "datatypes_uri.h"

#include <string>

Uri parseUri(const std::string& uri);

std::string deriveUriString(const Uri inputUri);

#endif
