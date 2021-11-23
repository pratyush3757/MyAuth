#ifndef _FILESYSTEM_IO_FILEHANDLER_H_
#define _FILESYSTEM_IO_FILEHANDLER_H_

#include "filesystem_io_uri.h"

#include <string>
#include <map>

std::map<int,Uri> readAuthDB(const std::string filename);

#endif
