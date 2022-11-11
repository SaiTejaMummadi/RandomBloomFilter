#include <iostream>
#include "sha256.h"
#include <cstring>
#include <cstdlib>


const unsigned int SHA256::sha256_k[64] = //UL = uint32
        {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
         0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
         0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
         0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
         0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
         0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
         0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
         0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
         0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void SHA256::transform(const unsigned char *message, unsigned int block_nb)
{
    uint32 w[64];
    uint32 wv[8];
    uint32 t1, t2;
    const unsigned char *sub_block;
    int i;
    int j;
    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);
        for (j = 0; j < 16; j++) {
            SHA2_PACK32(&sub_block[j << 2], &w[j]);
        }
        for (j = 16; j < 64; j++) {
            w[j] =  SHA256_F4(w[j -  2]) + w[j -  7] + SHA256_F3(w[j - 15]) + w[j - 16];
        }
        for (j = 0; j < 8; j++) {
            wv[j] = m_h[j];
        }
        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
                 + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (j = 0; j < 8; j++) {
            m_h[j] += wv[j];
        }
    }
}

void SHA256::init()
{
    m_h[0] = 0x6a09e667;
    m_h[1] = 0xbb67ae85;
    m_h[2] = 0x3c6ef372;
    m_h[3] = 0xa54ff53a;
    m_h[4] = 0x510e527f;
    m_h[5] = 0x9b05688c;
    m_h[6] = 0x1f83d9ab;
    m_h[7] = 0x5be0cd19;
    m_len = 0;
    m_tot_len = 0;
}

void SHA256::update(const unsigned char *message, unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;
    tmp_len = SHA224_256_BLOCK_SIZE - m_len;
    rem_len = len < tmp_len ? len : tmp_len;
    memcpy(&m_block[m_len], message, rem_len);
    if (m_len + len < SHA224_256_BLOCK_SIZE) {
        m_len += len;
        return;
    }
    new_len = len - rem_len;
    block_nb = new_len / SHA224_256_BLOCK_SIZE;
    shifted_message = message + rem_len;
    transform(m_block, 1);
    transform(shifted_message, block_nb);
    rem_len = new_len % SHA224_256_BLOCK_SIZE;
    memcpy(m_block, &shifted_message[block_nb << 6], rem_len);
    m_len = rem_len;
    m_tot_len += (block_nb + 1) << 6;
}

void SHA256::final(unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;
    int i;
    block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9)
                     < (m_len % SHA224_256_BLOCK_SIZE)));
    len_b = (m_tot_len + m_len) << 3;
    pm_len = block_nb << 6;
    memset(m_block + m_len, 0, pm_len - m_len);
    m_block[m_len] = 0x80;
    SHA2_UNPACK32(len_b, m_block + pm_len - 4);
    transform(m_block, block_nb);
    for (i = 0 ; i < 8; i++) {
        SHA2_UNPACK32(m_h[i], &digest[i << 2]);
    }
}

std::string sha256(std::string input)
{
    unsigned char digest[SHA256::DIGEST_SIZE];
    memset(digest,0,SHA256::DIGEST_SIZE);

    SHA256 ctx = SHA256();
    ctx.init();
    ctx.update( (unsigned char*)input.c_str(), input.length());
    ctx.final(digest);

    char buf[2*SHA256::DIGEST_SIZE+1];
    buf[2*SHA256::DIGEST_SIZE] = 0;
    for (int i = 0; i < SHA256::DIGEST_SIZE; i++)
        sprintf(buf+i*2, "%02x", digest[i]);
    return std::string(buf);
}



using std::string;
using std::cout;
using std::endl;
#include <bits/stdc++.h>

int hexadecimalToDecimal(string hexVal)
{
    int len = hexVal.size();

    // Initializing base value to 1, i.e 16^0
    int base = 1;

    int dec_val = 0;

    // Extracting characters as digits from last
    // character
    for (int i = len - 1; i >= 0; i--) {
        // if character lies in '0'-'9', converting
        // it to integral 0-9 by subtracting 48 from
        // ASCII value
        if (hexVal[i] >= '0' && hexVal[i] <= '9') {
            dec_val += (int(hexVal[i]) - 48) * base;

            // incrementing base by power
            base = base * 16;
        }

            // if character lies in 'A'-'F' , converting
            // it to integral 10 - 15 by subtracting 55
            // from ASCII value
        else if (hexVal[i] >= 'A' && hexVal[i] <= 'F') {
            dec_val += (int(hexVal[i]) - 55) * base;

            // incrementing base by power
            base = base * 16;
        }
    }
    return dec_val;
}

#include <ctime>
#include <iostream>
using namespace std;
#include <fstream>
#include<string>

int haship(string ip, int mval){
    string output1 = sha256(ip);
//        cout <<output1;
    int hashipdec = hexadecimalToDecimal(output1);

//    cout <<" ***\n"<<hashipdec;
    int hashipdecmod = abs(hashipdec % mval);
//    cout <<" ***\n"<<hashipdecmod;
    return hashipdecmod;
}


string makeip(){
    int random1 = rand();
    int random2 = rand();
    string strbase = "192.168.";
    random1 = 1+random1%10;
    random2 = 1+random2%999;

    string randstr1 = to_string(random1);
    string randstr2 = to_string(random2);
    string ip = strbase + randstr1 + "." + randstr2;
//    cout<<"\n"<<ip;
    return ip;
}


int main(int argc, char *argv[])
{
    //seeding time to get random numbers
    //192.168.X.XXX

    srand(time(0));

    //Inputting the M value
    int mval;
    cout << "Enter the M value which was used for Building RBF:";
    cin >> mval;

    //Scanning RBF file from the text file
    std::fstream myfile("RBFRow1.txt", std::ios_base::in);
    vector< vector<int>> rbfarray(2, vector<int> (mval));
    // int rbfarray[2][mval];
    float a;
    int count = 0;
    while (myfile >> a)
    {
        rbfarray[0][count] = a;
        if (a == 0){
            rbfarray[1][count] = 1;
        }
        else if (a == 1){
            rbfarray[1][count] = 0;
        }
        count++;
    }
    myfile.close();



//    for(int i=0;i<2;++i){
//        for(int j=0;j<mval;++j){
//
//            cout<<rbfarray[i][j]<<' ';
//        }
//        cout<<endl;
//    }
//    cout<<endl;
//Getting the choosen cell
    int mycount = 0;
    int chosenarray[mval];

    for(int j=0;j<mval;++j){

        mycount = mycount + 1;
        string mycountstr = to_string(mycount);
        string rbfinput = "0"+mycountstr;
//            cout<<rbfinput;
        string rbfoutput = sha256(rbfinput);
        int rbfhashint = hexadecimalToDecimal(rbfoutput);
//            cout <<" ***\n"<<rbfhashint;
        int rbfhashmod = abs(rbfhashint % 2);
        if(rbfhashmod == 0){
            chosenarray[j] = rbfarray[0][j];
        }
        else if (rbfhashmod == 1){
            chosenarray[j] = rbfarray[1][j];
        }

//            bigr[i][j] = mycount;
    }

//    for(int j=0;j<mval;++j){
//        cout<<chosenarray[j]<<' ';
//    }




    string ipaddress;
    cout <<"Enter IP address: ";
    cin>>ipaddress;
//    cout<<ipaddress;
    int storehashnum[8];
    for(int k=1;k<9;k++){
        string finalip = to_string(k) + ipaddress;
        int hashnumval = haship(finalip,mval);
//            cout<<hashnumval<<"\n";
        storehashnum[k-1] = hashnumval;
    }
//    for(int j=0;j<8;++j){
//        cout<<" "<<storehashnum[j]<<' ';
//    }
    int flagval = 99;
    for (int i=0;i<8;i++){
        int myad = storehashnum[i];
        if (chosenarray[myad] == 0){
            flagval = 0;
        }
    }



    if (flagval == 0){
        cout<<"\n"<<"Pass";
    }
    else if (flagval == 99){
        cout<<"\n"<<"Block";
    }

    return 0;

}








//BACKUP CHECKERS


//    for (int i=0;i<10000;i++){
//        string ipaddress = makeip();
//        int storehashnum[8];
//        for(int k=1;k<9;k++){
//            string finalip = to_string(k) + ipaddress;
//            int hashnumval = haship(finalip,mval);
////            cout<<hashnumval<<"\n";
//            storehashnum[k-1] = hashnumval;
//            if (bigr[0][hashnumval] ==0){
//                bigr[0][hashnumval] = 1;
//                bigr[1][hashnumval] = 0;
//            }
//            else if (bigr[0][hashnumval] ==1){
//                bigr[0][hashnumval] = 0;
//                bigr[1][hashnumval] = 1;
//            }
//        }
//
//    }



//    cout<<"\n"<<mval;


//    string temp = makeip();
//    cout<<"\n"<<temp;


//    cout<<"\n"<<mval;
//    int temp2 = haship(temp,mval);
//    cout<<"\n"<<temp2;





    //generating ip and concate
//    for (int i=0;i<1;i++){
//        int random1 = rand();
//        int random2 = rand();
//        string strbase = "192.168.";
//        random1 = 1+random1%10;
//        random2 = 1+random2%999;
//
//        string randstr1 = to_string(random1);
//        string randstr2 = to_string(random2);
//        string ip = strbase + randstr1 + "." + randstr2;
//        cout<<"\n"<<ip;
//        string output1 = sha256(ip);
//        cout <<output1;
//        int hashipdec = hexadecimalToDecimal(output1);

//        cout <<" ***\n"<<hashipdec;
//        int hashipdecmod = abs(hashipdec % mval);
//        cout <<" ***\n"<<hashipdecmod;
    //generating ip and concate

//        cout<<"\n***\n"<<random1<<"*******"<<random2;
//    }

//    int randomin = rand();
//    randomin = 1+randomin%10;
//    cout<<"\n***\n"<<randomin;

    //Checking the sha256 function
//    string input = "192.168.7.833";
//    string output1 = sha256(input);
////    cout <<output1;
//    printf("***************************************************************************\n");
//    cout <<"\n****\n"<< (hexadecimalToDecimal(output1));

    //cout<<"#$$$%"<<rand();

    //int randomin = rand();
    //cout<<"\n***\n"<<1+randomin%10;


    //checking the hash function
    //    string test1 = "192.168.4.15";
//    int temp3 = haship(test1,mval);
//    cout<<"\n"<<temp3;

//    return 0;
//}