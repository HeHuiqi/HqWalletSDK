//
//  CRIPEMD160.hpp
//  HqWalletSDK
//
//  Created by hehuiqi on 2020/11/21.
//

#ifndef CRIPEMD160_hpp
#define CRIPEMD160_hpp

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

class CRIPEMD160{
    
private:
    uint32_t s[5];
    unsigned char buf[64];
    uint64_t bytes;

public:
    static const size_t OUTPUT_SIZE = 20;

    CRIPEMD160();
    CRIPEMD160& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CRIPEMD160& Reset();
};

#endif /* CRIPEMD160_hpp */
