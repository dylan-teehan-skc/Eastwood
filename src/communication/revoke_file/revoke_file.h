
#ifndef REVOKE_FILE_H
#define REVOKE_FILE_H
#include <string>
#include <vector>

void refresh_access(const std::vector<std::string> &allowed_usernames, const std::string &file_uuid);

#endif //REVOKE_FILE_H
