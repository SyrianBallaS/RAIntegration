#include "RA_md5factory.h"

#include "RA_Defs.h"

_CONSTANT_VAR MD5_STRING_LEN = 32;

std::string RAGenerateMD5(const std::string& sStringToMD5)
{
    Expects(!sStringToMD5.empty());
    md5_state_t pms{};
    std::array<md5_byte_t, 16> digest{};

    std::basic_string<md5_byte_t> sDataBuffer;
    for (const md5_byte_t ch : sStringToMD5)
        sDataBuffer.push_back(ch);

    md5_init(&pms);
    md5_append(&pms, sDataBuffer.c_str(), sStringToMD5.length());
    md5_finish(&pms, std::data(digest));

    std::array<char, MD5_STRING_LEN + 1> buffer{};
    Ensures(sprintf_s(std::data(buffer), MD5_STRING_LEN + 1,
                      "%02x%02x%02x%02x%02x%02x%02x%02x"
                      "%02x%02x%02x%02x%02x%02x%02x%02x",
                      digest.at(0), digest.at(1), digest.at(2), digest.at(3), digest.at(4), digest.at(5), digest.at(6),
                      digest.at(7), digest.at(8), digest.at(9), digest.at(10), digest.at(11), digest.at(12),
                      digest.at(13), digest.at(14), digest.at(15)) >= 0);

    return std::data(buffer);
}

std::string RAGenerateMD5(const BYTE* pRawData, size_t nDataLen)
{
    md5_state_t pms{};
    std::array<md5_byte_t, 16> digest{};

    static_assert(sizeof(md5_byte_t) == sizeof(BYTE), "Must be equivalent for the MD5 to work!");

    md5_init(&pms);
    md5_append(&pms, pRawData, nDataLen);
    md5_finish(&pms, std::data(digest));

    std::array<char, MD5_STRING_LEN + 1> buffer{};
    Ensures(sprintf_s(std::data(buffer), MD5_STRING_LEN + 1,
                      "%02x%02x%02x%02x%02x%02x%02x%02x"
                      "%02x%02x%02x%02x%02x%02x%02x%02x",
                      digest.at(0), digest.at(1), digest.at(2), digest.at(3), digest.at(4), digest.at(5), digest.at(6),
                      digest.at(7), digest.at(8), digest.at(9), digest.at(10), digest.at(11), digest.at(12),
                      digest.at(13), digest.at(14), digest.at(15)) >= 0);

    return std::data(buffer); // Implicit promotion to std::string
}

std::string RAGenerateMD5(std::vector<BYTE>&& DataIn)
{
    const auto _DataIn = std::move(DataIn);
    return RAGenerateMD5(_DataIn.data(), _DataIn.size());
}
