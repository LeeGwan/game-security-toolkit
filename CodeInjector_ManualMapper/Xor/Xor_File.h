#pragma once
#include <fstream>
#include <vector>

typedef unsigned char BYTE;

class Xor_File
{
public:
    Xor_File();
    BYTE* Xor_dll(BYTE* original, std::streampos fileSize);

private:
    std::vector<uint8_t> key;
};