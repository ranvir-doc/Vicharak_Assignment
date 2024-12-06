#include "licesnce.cpp"
#include <cstring>
#include <sstream>
#include <iomanip>
const uint32_t SHA256::ROUND_CONSTANT[64]={
    0x428a2f98,0x71374491,0xc67178f2
};
SHA256::SHA256(){
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
    bufferFillSize = 0;
    totalBitsProcessed = 0;


}

void SHA256::addData(const uint8_t* input, size_t length){
    size_t bytesToProcess = 0;
    while(length>0){
        bytesToProcess = std::min(length, 64 - bufferFillSize);
        std::memcpy(buffer + bufferFillSize,input,bytesToProcess);
        bufferFillSize += bytesToProcess;
        length -= bytesToProcess;
        input += bytesToProcess;
        if(bufferFillSize == 64){
            processBlock(buffer);
            bufferFillSize = 0;
        }

    }
}

std::string SHA256::computeHash() {
    buffer[bufferFillSize]= 0x80;
    std::memset(buffer + bufferFillSize + 1, 0, 64 - bufferFillSize - 1);
    if(bufferFillSize >=56){
        processBlock(buffer);
        std::memset(buffer, 0, 64);

    }
    uint64_t bitLength = totalBitsProcessed*8;
    for(int i =0; i<8; ++i){
        buffer[63-i]=bitLength & 0xFF;
        bitLength >>=8;

    }
    processBlock(buffer);
    std::ostringstream hashStream;
    for(int i = 0 ; i<8; ++i){
        hashStream<<std::hex<<std::setw(8)<<std::setfill('0')<<state[i];
    }
    return hashStream.str();


}

void SHA256::processBlock(const uint8_t*block){
    uint32_t W[64];
    for(int t=0;t<16;++t){
        W[t] = (block[t*4]<<24)| (block[t*4+1]<<16)|(block[t*4+2]<<8)| block[t*4+3];
    }
    for(int t = 16; t<64; ++t){
        W[t] = lowerSigma1(W[t-2])+ W[t-7]+ lowerSigma0(W[t-15])+ W[t-16];

    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7]; 

    for (int t=0;t<64;++t){
        uint32_t T1=h+upperSigma1(e) + choose(e,f,g) + ROUND_CONSTANT[t]+W[t];
        uint32_t T2=upperSigma0(a) + majority(a,b,c);
        h=g;g=f;f=e;e=d+T1;
        d=c;c=b;b=a;a=T1+T2;

    }
    state[0]+=a; state[1] +=b; state[2] +=c;state[3]+=d;
    state[4]+=e; state[5] +=f; state[6] +=g;state[7]+=h;

}

uint32_t SHA256::rotateRight(uint32_t value, uint32_t shift){
    return (value>> shift)|(value<<(32-shift));

}

uint32_t SHA256::choose(uint32_t x, uint32_t y, uint32_t z){
    return (x&y)^(~x&z);


}

uint32_t SHA256::majority(uint32_t x, uint32_t y, uint32_t z){
    return (x&y)^(x&z)^(y&z);

}

uint32_t SHA256::upperSigma0(uint32_t x){
    return rotateRight(x,2)^rotateRight(x,13)^rotateRight(x,22);

}

uint32_t SHA256::upperSigma1(uint32_t x){
    return rotateRight(x,6)^rotateRight(x,11)^rotateRight(x,25);

}

uint32_t SHA256::lowerSigma0(uint32_t x){
    return rotateRight(x,7)^rotateRight(x,18)^(x>>3);

}

uint32_t SHA256::lowerSigma1(uint32_t x){
    return rotateRight(x,17)^rotateRight(x,19)^(x>>10);

}
