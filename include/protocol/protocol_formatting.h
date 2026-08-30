#pragma once
#include "protocol/request.h"
#include "protocol/response.h"

std::ostream& operator<<(std::ostream& os, const RequestHeader& header);
std::ostream& operator<<(std::ostream& os, const ResponseHeader& header);
std::ostream& operator<<(std::ostream& os, const RequestPayload& payload);
std::ostream& operator<<(std::ostream& os, const ResponsePayload& payload);
std::ostream& operator<<(std::ostream& os, Request& request);
std::ostream& operator<<(std::ostream& os, const Response& response);
void hexify(const char* buffer, size_t start, size_t end);
