#include<stdio.h>
#include<iostream>
#include<sys/socket.h>
#include<netinet/in.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<string.h>
#include <pthread.h>

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS 1
#include<fstream>
#include<vector>
#include<algorithm>
#include<cmath>
//下面这个是密码学写的
char message[65];//每一轮加密就用这个
//下面这个是为了网络安全技术加的
char allMessage[960];//15*64=960 最大的输入长度 一次最多输入120个字符（960/8）
char cinedMessage[120]; //用户从命令行输入，最多120个字符

//下面这些是密码学写的
char decrypKey[17][49];//解密用的密钥
char originRight[33];//原始的，后来要用于给左侧赋值的32位数
char Left[33];//左侧的32比特
char Right[33];//右侧的32比特
char Right48[49];//记录扩展后的右侧48比特
char key[65];//输入的密钥为64位
char Key[57];//真正用的密钥是56位
char LeftKey[29];//左边的28位密钥
char RightKey[29];//右边的28位密钥
char Key48[49];//用来做异或运算的48位密钥
int IP[] = { 58, 50, 42, 34, 26, 18, 10, 2,
             60, 52, 44, 36, 28, 20, 12, 4,
             62, 54, 46, 38, 30, 22, 14, 6,
             64, 56, 48, 40, 32, 24, 16, 8,
             57, 49, 41, 33, 25, 17, 9,  1,
             59, 51, 43, 35, 27, 19, 11, 3,
             61, 53, 45, 37, 29, 21, 13, 5,
             63, 55, 47, 39, 31, 23, 15, 7 };//初始置换IP
// 尾置换表
int IP_1[] = { 40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41,  9, 49, 17, 57, 25 };
int E[] = { 32,  1,  2,  3,  4,  5,
            4,  5,  6,  7,  8,  9,
            8,  9, 10, 11, 12, 13,
           12, 13, 14, 15, 16, 17,
           16, 17, 18, 19, 20, 21,
           20, 21, 22, 23, 24, 25,
           24, 25, 26, 27, 28, 29,
           28, 29, 30, 31, 32,  1 };//扩展置换表E
int PC_1[] = { 57, 49, 41, 33, 25, 17, 9,
               1, 58, 50, 42, 34, 26, 18,
              10,  2, 59, 51, 43, 35, 27,
              19, 11,  3, 60, 52, 44, 36,
              63, 55, 47, 39, 31, 23, 15,
               7, 62, 54, 46, 38, 30, 22,
              14,  6, 61, 53, 45, 37, 29,
              21, 13,  5, 28, 20, 12,  4 };// 密钥置换表，将64位密钥变成56位
int PC_2[] = { 14, 17, 11, 24,  1,  5,
               3, 28, 15,  6, 21, 10,
              23, 19, 12,  4, 26,  8,
              16,  7, 27, 20, 13,  2,
              41, 52, 31, 37, 47, 55,
              30, 40, 51, 45, 33, 48,
              44, 49, 39, 56, 34, 53,
              46, 42, 50, 36, 29, 32 };// 压缩置换，将56位密钥压缩成48位子密钥
int shiftBits[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };// 每轮左移的位数
// S盒，每个S盒是4x16的置换表，6位 -> 4位
int S_BOX[8][4][16] = {
    {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
    },
    {
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
    },
    {
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
    },
    {
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
    },
    {
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
    },
    {
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
    },
    {
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
    },
    {
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    }
};
//P置换表
int P[] = { 16,  7, 20, 21,
           29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2,  8, 24, 14,
           32, 27,  3,  9,
           19, 13, 30,  6,
           22, 11,  4, 25 };

void setleft() {
    for (int i = 1; i <= 32; i++) {
        Left[i] = message[i];
    }
}
void setright() {
    for (int i = 1; i <= 32; i++) {
        Right[i] = message[32 + i];
    }
}
//初始置换
void initialChange() {
    char temp[65];
    for (int i = 1; i < 65; i++) {
        temp[i] = message[IP[i-1]];
    }
    for (int i = 1; i < 65; i++) {
        message[i] = temp[i];
    }
}
void reverseInitialChange() {
    for (int i = 1; i <= 64; i++) {
        if (i <= 32) {
            message[i] = Left[i];
        }
        else {
            message[i] = Right[i - 32];
        }
    }
    char temp[65];
    for (int i = 1; i <= 64; i++) {
        temp[i] = message[i];
    }
    for (int i = 1; i < 65; i++) {
        message[i] = temp[IP_1[i - 1]];
    }
}
//扩展置换E表
void extendChange() {
    char temp[33];
    for (int i = 1; i < 33; i++) {
        temp[i] = Right[i];
    }
    for (int i = 1; i < 49; i++) {
        Right48[i] = temp[E[i - 1]];
    }
}
//计算异或运算
void calXOR() {
    char temp[49];
    for (int i = 1; i < 49; i++) {
        if (Key48[i] == Right48[i]) {
            temp[i] = '0';
            continue;
        }
        else {
            temp[i] = '1';
            continue;
        }
    }
    for (int i = 1; i < 49; i++) {
        Right48[i] = temp[i];
    }
}
//解密时的异或运算
void DecryptCalXOR(int n) {
    char temp[49];
    for (int i = 1; i < 49; i++) {
        if (decrypKey[n][i] == Right48[i]) {
            temp[i] = '0';
            continue;
        }
        else {
            temp[i] = '1';
            continue;
        }
    }
    for (int i = 1; i < 49; i++) {
        Right48[i] = temp[i];
    }
}
//完成密钥的64--》56的置换
void getRealKey() {
    char temp[57];
    for (int i = 1; i < 57; i++) {
        temp[i] = key[PC_1[i - 1]];
    }
    for (int i = 1; i < 65; i++) {
        Key[i] = temp[i];
    }
}
void setLeftKey() {
    for (int i = 1; i < 29; i++) {
        LeftKey[i] = Key[i];
    }
}
void setRightKey() {
    for (int i = 1; i < 29; i++) {
        RightKey[i] = Key[28 + i];
    }
}
//密钥左移函数
void shiftKey(int n) {
    char temp[29];
    for (int i = 1; i < 29; i++) {
        temp[i] = LeftKey[i];
    }
    for (int i = 1; i < 29; i++) {
        if (i + n <= 28) {
            LeftKey[i] = temp[i + n];
        }
        else {
            LeftKey[i] = temp[i + n - 28];
        }
    }

    for (int i = 1; i < 29; i++) {
        temp[i] = RightKey[i];
    }
    for (int i = 1; i < 29; i++) {
        if (i + n <= 28) {
            RightKey[i] = temp[i + n];
        }
        else {
            RightKey[i] = temp[i + n - 28];
        }
    }
}
//完成密钥置换2
void getUsedKey() {
    char temp[57];//拿到现在的56比特
    for (int i = 1; i < 57; i++) {
        if (i < 29) {
            temp[i] = LeftKey[i];
        }
        else {
            temp[i] = RightKey[i - 28];
        }
    }
    for (int i = 1; i < 49; i++) {
        Key48[i] = temp[PC_2[i - 1]];
    }
}
int getRow(char a, char b) {
    if (a == '0' && b == '0') { return 0; }
    if (a == '0' && b == '1') { return 1; }
    if (a == '1' && b == '0') { return 2; }
    if (a == '1' && b == '1') { return 3; }
    std::cout<<"----getRow()函数错误----"<<std::endl;
    return -1;
}
int getColumn(char a, char b, char c, char d) {
    if (a == '0' && b == '0' && c == '0' && d == '0') { return 0; }
    if (a == '0' && b == '0' && c == '0' && d == '1') { return 1; }
    if (a == '0' && b == '0' && c == '1' && d == '0') { return 2; }
    if (a == '0' && b == '0' && c == '1' && d == '1') { return 3; }
    if (a == '0' && b == '1' && c == '0' && d == '0') { return 4; }
    if (a == '0' && b == '1' && c == '0' && d == '1') { return 5; }
    if (a == '0' && b == '1' && c == '1' && d == '0') { return 6; }
    if (a == '0' && b == '1' && c == '1' && d == '1') { return 7; }
    if (a == '1' && b == '0' && c == '0' && d == '0') { return 8; }
    if (a == '1' && b == '0' && c == '0' && d == '1') { return 9; }
    if (a == '1' && b == '0' && c == '1' && d == '0') { return 10; }
    if (a == '1' && b == '0' && c == '1' && d == '1') { return 11; }
    if (a == '1' && b == '1' && c == '0' && d == '0') { return 12; }
    if (a == '1' && b == '1' && c == '0' && d == '1') { return 13; }
    if (a == '1' && b == '1' && c == '1' && d == '0') { return 14; }
    if (a == '1' && b == '1' && c == '1' && d == '1') { return 15; }
    std::cout<<"----getColumn()函数错误----"<<std::endl;
    return -1;
}
std::string int2string(int i) {
    if (i == 0) { return "0000"; }
    if (i == 1) { return "0001"; }
    if (i == 2) { return "0010"; }
    if (i == 3) { return "0011"; }
    if (i == 4) { return "0100"; }
    if (i == 5) { return "0101"; }
    if (i == 6) { return "0110"; }
    if (i == 7) { return "0111"; }
    if (i == 8) { return "1000"; }
    if (i == 9) { return "1001"; }
    if (i == 10) { return "1010"; }
    if (i == 11) { return "1011"; }
    if (i == 12) { return "1100"; }
    if (i == 13) { return "1101"; }
    if (i == 14) { return "1110"; }
    if (i == 15) { return "1111"; }
    std::cout<<"----int2string()函数错误----"<<std::endl;
    return "";
}
void SBoxChange() {
    for (int i = 1; i <= 8; i++) {
        char temp[7];
        for (int j = 1; j <= 6; j++) {
            temp[j] = Right48[(i - 1) * 6 + j];
        }
        int r = getRow(temp[1], temp[6]);
        int c = getColumn(temp[2], temp[3], temp[4], temp[5]);
        int result = S_BOX[i - 1][r][c];
        std::string s = int2string(result);
        for (int k = 1; k <= 4; k++) {
            Right[(i - 1) * 4 + k] = s[k-1];
        }
    }
}
//P置换
void PChange() {
    char temp[33];
    for (int i = 1; i < 33; i++) {
        temp[i] = Right[i];
    }
    for (int i = 1; i < 33; i++) {
        Right[i] = temp[P[i - 1]];
    }
}
//最后一次异或运算
void calXOR2() {
    for (int i = 1; i < 33; i++) {
        if (Right[i] == Left[i]) {
            Right[i] = '0';
        }
        else {
            Right[i] = '1';
        }
    }
}
void setOriginRight() {
    for (int i = 1; i <= 32; i++) {
        originRight[i] = Right[i];
    }
}
void changeLR() {
    for (int i = 1; i < 33; i++) {
        Left[i] = originRight[i];
    }
    
}
void finalChangeLR() {
    char temp[33];
    for (int i = 1; i < 33; i++) {
        temp[i] = Left[i];
        Left[i] = Right[i];
        Right[i] = temp[i];
    }
}
void getDecryptKey() {
    for (int i = 1; i <= 16; i++) {
        shiftKey(shiftBits[i - 1]);//移位
        getUsedKey();//选择需要的48位
        for (int j = 1; j <= 48; j++) {
            decrypKey[16 - i + 1][j] = Key48[j];//置位
        }
    }
}

void EncryptDESround(int r) {
    setOriginRight();
    extendChange();//扩展置换
    //printcstar64(Right, 1, 33);
    //printcstar48(Right48, 1, 49);
    shiftKey(shiftBits[r-1]);//移动密钥
    getUsedKey();//完成密钥置换2
    //printcstar48(Key48, 1, 49);
    calXOR();
    //printcstar48(Right48, 1, 49);
    SBoxChange();
    //printcstar64(Right, 1, 33);
    PChange();
    calXOR2();
    changeLR();
}
void DecryptDESround(int r) {
    setOriginRight();
    extendChange();//扩展置换
    //printcstar64(Right, 1, 33);
    //printcstar48(Right48, 1, 49);
    //shiftKey(shiftBits[r - 1]);//移动密钥
    //getUsedKey();//完成密钥置换2
    //printcstar48(Key48, 1, 49);
    DecryptCalXOR(r);
    //printcstar48(Right48, 1, 49);
    SBoxChange();
    //printcstar64(Right, 1, 33);
    PChange();
    calXOR2();
    changeLR();
}
void printcstar64(char* c,int start,int end) {
    for (int i = start; i <end; i++) {
        std::cout << c[i];
        //cout << int(c[i]);
        if (i % 8 == 0) { std::cout << std::endl; }
    }
    std::cout << std::endl;
}
void printcstar48(char* c, int start, int end) {
    for (int i = start; i < end; i++) {
        std::cout << c[i];
        if (i % 6 == 0) { std::cout << std::endl; }
    }
    std::cout << std::endl;
}
std::string h2b(char c) {
    if (c >= 65 && c <= 90) {
        c += 32;
    }
    switch (c)
    {
    case '0':
        return "0000";
        break;
    case '1':
        return "0001";
        break;
    case '2':
        return "0010";
        break;
    case '3':
        return "0011";
        break;
    case '4':
        return "0100";
        break;
    case '5':
        return "0101";
        break;
    case '6':
        return "0110";
        break;
    case '7':
        return "0111";
        break;
    case '8':
        return "1000";
        break;
    case '9':
        return "1001";
        break;
    case 'a':
        return "1010";
        break;
    case 'b':
        return "1011";
        break;
    case 'c':
        return "1100";
        break;
    case 'd':
        return "1101";
        break;
    case 'e':
        return "1110";
        break;
    case 'f':
        return "1111";
        break;
    default:
        return "error";
        break;
    }
}

void printCstar(char* cs,int len){
    int i=0;
    while(i!=len){
        std::cout<<cs[i];
        if((i+1)%8==0){
            std::cout<<std::endl;
        }
        i++;
    }
}

std::string C2B(char c){
    int temp = int(c);
    std::vector<int>vi;
    while(temp>1){
        int y = temp%2;
        temp/=2;
        vi.push_back(y);
    }
    vi.push_back(temp);
    std::vector<int>trans;
    for(int i=1;i<=8-vi.size();i++){
        trans.push_back(0);
    }
    for(int i=vi.size()-1;i>=0;i--){
        trans.push_back(vi[i]);
    }
    std::string s="";
    for(int i=0;i<=7;i++){
        if(trans[i]==1){s.append("1");}
        if(trans[i]==0){s.append("0");}
    }
    return s;
} 

void fillAllMessage(){
    memset(cinedMessage,0,120);
    memset(allMessage,0,960);
    std::cin.getline(cinedMessage,120);
    int i=0;
    while(int(cinedMessage[i])!=0){
        char c = cinedMessage[i];
        std::string s = C2B(c);
        memcpy(allMessage+(8*i),s.c_str(),8);
        i++;
    }
    //printCstar(allMessage,i*8);
}

char B2C(std::string s){
    int temp=0;
    for(int i=0;i<=7;i++){
        if(s[i]=='0'){continue;}
        else{
            temp+=pow(2,7-i);
        }
    }
    return char(temp);
}

int getAllMessageLen(){
    int i=0;
    while((int)allMessage[i]!=0){
        i++;
    }
    return i;
}

void loadkey(){
    memset(key, 0, 65);
    std::string path="key.txt";
    // std::cout << "请输入要读取的密钥文件路径" << std::endl;
    // std::cin >> path;
    // getchar();
    std::ifstream infile;
    infile.open(path, std::ios::in);
    if (!infile.is_open()) {
        std::cout << "读取文件失败" << std::endl;
        return;
    }
    char buff[1000];
    char tempbuff[1000];
    while (infile.getline(tempbuff, 1000)) {
        std::cout << "正在读取...." << std::endl;
        for (int i = 0; i < 1000; i++) {
            if (tempbuff[i] != '\0') {
                buff[i] = tempbuff[i];
                continue;
            }
            else {
                buff[i] = '\0';
                break;
            }
        }
    }
    int count = 0;
    int i = 0;
    while (count < 8 && buff[i] != '\0') {
        if (i >= 1 && buff[i - 1] == '0' && buff[i] == 'x') {
            //cout << buff[i+1] << buff[i + 2] << endl;
            std::string front = h2b(buff[i + 1]);
            if (front == "error") { std::cout<<"输入错误"<<std::endl;return ; }
            std::string back = h2b(buff[i + 2]);
            if (back == "error") { std::cout<<"输入错误"<<std::endl;return ; }
            front = front.append(back);
            //cout << front << endl;
            strcpy(key + (count * 8 + 1), front.data());
            i += 2;
            count++;
            continue;
        }
        else {
            i += 1;
            continue;
        }
    }
}

std::string realencrypt(){
    //std::cout<<"加密前为"<<std::endl;
    //printcstar64(message, 1, 65);//打印数据
    loadkey();//载入密钥
    //std::cout << "----您输入的密钥为----:" << std::endl;
    //printcstar64(key, 1, 65);//打印输入的密钥

    getRealKey();//产生真的密钥
    //std::cout << "真正使用的56位密钥是" << std::endl;
    //printcstar64(Key, 1, 57);//打印真正的密钥

    initialChange();//初始置换
    //cout << "初始置换后得到的明文为" << endl;
    //printcstar64(message, 1, 65);//打印数据

    //现在进入这里就默认message中已经填充了64位的数据，Key中填好了56位数据
    setleft(); setright();//填充左右部分明文
    setLeftKey(); setRightKey();//填充左右部分密文

    for (int i = 1; i <= 16; i++) {
        EncryptDESround(i);
    }
    finalChangeLR();
    reverseInitialChange();
    //std::cout << "----加密结果为----" << std::endl;
    //printcstar64(message, 1, 65);//打印数据
    std::string s="";
    for(int i=1;i<=64;i++){
        s.push_back(message[i]);
    }
    return s;
}

std::string realdecrypt(){
    loadkey();//载入密钥
    //cout << "您输入的密钥为：" << endl;
    //printcstar64(key, 1, 65);//打印输入的密钥

    getRealKey();//产生真的密钥
    //cout << "真正使用的56位密钥是" << endl;
    //printcstar64(Key, 1, 57);//打印真正的密钥

    initialChange();//初始置换
    //cout << "初始置换后得到的明文为" << endl;
    //printcstar64(message, 1, 65);//打印数据

    //现在进入这里就默认message中已经填充了64位的数据，Key中填好了56位数据
    setleft(); setright();//填充左右部分明文
    setLeftKey(); setRightKey();//填充左右部分密文

    //但是在这里需要考虑的一点是 需要使用和初始置换相反的密钥
    getDecryptKey();
    for (int i = 1; i <= 16; i++) {
        DecryptDESround(i);
    }
    finalChangeLR();
    reverseInitialChange();
    //std::cout << "----解密结果为----" << std::endl;
    //printcstar64(message, 1, 65);//打印数据
    std::string ss="";
    for(int i=1;i<=64;i++){
        ss.push_back(message[i]);
    }
    return ss;
}

void encryptMessage() {
    fillAllMessage();
    int i=0;
    int len=getAllMessageLen();
    //std::cout<<"----比特数为："<<len<<"----"<<std::endl;
    while (true)
    {   
        if(i*64+64<=len){
            memcpy(message,allMessage+(i*64),64);
            //完成加密动作
            //std::cout<<"----第"<<i+1<<"轮加密----"<<std::endl;
            realencrypt();
            i++;
            continue;
        }else{
            //每一次fillAllMessage函数都会把内存全都置零
            memcpy(message,allMessage+(i*64),64);
            //完成加密动作
            //std::cout<<"----第"<<i+1<<"轮加密----"<<std::endl;
            realencrypt();
            i++;
            break;
        }
    }
    //std::cout<<"here"<<std::endl;
}

std::string EnryptForTCP(std::string s){
    memset(cinedMessage,0,120);
    memset(allMessage,0,960);
    memset(message,0,65);
    int i;
    for(i=0;i<s.size();i++){
        std::string temp = C2B(s[i]);
        memcpy(allMessage+(8*i),temp.c_str(),8);
    }
    //printCstar(allMessage,i*8);
    i=0;//赋予一个新值
    int len=getAllMessageLen();
    //std::cout<<"----比特数为："<<len<<"----"<<std::endl;
    std::string ss = "";
    while (true)
    {   
        memset(message,0,65);
        if(i*64+64<len){
            memcpy(message+1,allMessage+(i*64),64);
            //完成加密动作
            //std::cout<<"----第"<<i+1<<"轮加密----"<<std::endl;
            ss.append(realencrypt());
            i++;
            continue;
        }else{
            //每一次fillAllMessage函数都会把内存全都置零
            memcpy(message+1,allMessage+(i*64),64);
            for(int j=1;j<=64;j++){
                if(int(message[j])==0){
                    message[j]='0';
                }
            }
            //完成加密动作
            //std::cout<<"----第"<<i+1<<"轮加密----"<<std::endl;
            ss.append(realencrypt());
            i++;
            break;
        }
    }
    return ss;
}


void decryptMessage(){
    int i=0;
    int len=getAllMessageLen();
    while (true)
    {   
        if(i*64+64<len){
            memcpy(message+1,allMessage+(i*64),64);
            i++;
            //完成加密动作
            //std::cout<<"----第"<<i+1<<"轮解密----"<<std::endl;
            realdecrypt();
            continue;
        }else{
            //每一次fillAllMessage函数都会把内存全都置零
            memcpy(message+1,allMessage+(i*64),64);
            i++;
            //完成加密动作
            //std::cout<<"----第"<<i+1<<"轮解密----"<<std::endl;
            realdecrypt();
            break;
        }

    }
}


char B2C(std::string s,int start){
    int ans=0;
    for(int i=0;i<=7;i++){
        if(s[start+i]=='0'){
            continue;
        }else{
            ans+=pow(2,7-i);
        }
    }
    return char(ans);
}


std::string DecryptForTCP(std::string s){
    memset(cinedMessage,0,120);
    memset(allMessage,0,960);
    memset(message,0,65);
    if(s.size()%8!=0){
        std::cout<<"接受信息错误"<<std::endl;
        return "";
    }
    memcpy(allMessage,s.c_str(),s.size());//长度对齐这里肯定是有问题的
    int i=0;
    int len=getAllMessageLen();
    std::string ss="";
    while (true)
    {   
        if(i*64+64<len){
            memcpy(message+1,allMessage+(i*64),64);
            //完成解密动作
            //std::cout<<"----第"<<i+1<<"轮解密----"<<std::endl;
            ss.append(realdecrypt());
            i++;
            continue;
        }else{
            //每一次fillAllMessage函数都会把内存全都置零
            memcpy(message+1,allMessage+(i*64),64);
            for(int j=1;j<=64;j++){
                if(int(message[j])==0){
                    message[j]='0';
                }
            }
            //完成解密动作
            //std::cout<<"----第"<<i+1<<"轮解密----"<<std::endl;
            ss.append(realdecrypt());
            i++;
            break;
        }

    }
    if(ss.size()%8!=0){
        std::cout<<"接受信息错误"<<std::endl;
        return "";
    }
    std::string ret="";
    for(int i=0;i<ss.size()/8;i++){
        ret.push_back(B2C(ss,i*8));
    }
    return ret;
}



int serv_sock;
bool quit=false;

class Node_server{
public:
    struct sockaddr_in client;
    int fd;
};

//创建套接字
int CreateSock(){
    int serverSock = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    return serverSock;
}

//初始化socket元素
sockaddr_in CreateSockAddrIn(std::string ip,int port){
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(ip.c_str());
	serv_addr.sin_port = htons(port);
    return serv_addr;
}


void *pthread_send_server(void* arg){
    std::cout<<"成功创建发送线程"<<std::endl;
    char buffer[7500];
    Node_server*node = (Node_server*)arg;
    while(true){
        std::cin.getline(buffer,900);
        //getchar();
        std::string s = buffer;
        std::string fin = "quit";
        if(s.find(fin)!=std::string::npos){
            quit=true;
            break;
        }
        if(s.size()>900){
            std::cout<<"输入过长，请重新输入"<<std::endl;
            continue;
        }
        //现在s和buffer中存储了同样的内容，要把这个内容传送给加密函数加密。
        s = EnryptForTCP(s);//对输入的内容进行DES加密
        memset(buffer,0,7500);
        memcpy(buffer,s.c_str(),s.size());
        int ret = send(node->fd,buffer,7500,0);
        if(ret==-1){
            std::cout<<"发送失败"<<std::endl;
            //std::cout<<errno<<std::endl;
        }else{
            std::cout<<"发送成功"<<std::endl;
        }
        memset(buffer,0,7500);
    }
    return nullptr;
}

void *pthread_recv_server(void* arg){
    std::cout<<"成功创建接收线程"<<std::endl;
    char buffer[7500];
    int sockfd = ((Node_server*)arg)->fd;
    while(true){
        int ret = recv(sockfd,buffer,7500,0);
        if(ret>0){
            std::string s = buffer;
            //std::cout<<s<<std::endl;
            s = DecryptForTCP(s);
            std::cout<<s<<std::endl;
        }
        memset(buffer,0,7500);
        if(quit){
            break;
        }
    }
    return nullptr;
}

void *pthread_accept(void *arg){
    std::cout<<"成功创建监听线程"<<std::endl;
    struct sockaddr_in clientSock;
    socklen_t clientLen = sizeof(clientSock);
    //accpet
    int acceptedFd = accept(serv_sock, (sockaddr *)&clientSock, &clientLen);
    std::cout<<"成功连接客户端"<<std::endl;
    Node_server* node=new Node_server();
    node->client = clientSock;
    node->fd = acceptedFd;
    pthread_t pthreadSend;
    pthread_t pthreadRecv;
    pthread_create(&pthreadSend,NULL,pthread_send_server,(void *)node);
    pthread_create(&pthreadRecv,NULL,pthread_recv_server,(void *)node); 
    
    while(true){
        if(quit){
            close(acceptedFd);
            break;
        }
    }
    return nullptr;
}

int Servermain(std::string s,int port){
    serv_sock = CreateSock();
    struct sockaddr_in serv_addr = CreateSockAddrIn("127.0.0.1",port);
    std::cout<<"ip、端口绑定完成"<<std::endl;
    //绑定文件描述符和服务器的ip和端口号
    bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    //进入监听状态，等待用户发起请求
	listen(serv_sock, 5);
    //创建专门accept的线程
    pthread_t acceptPthread;
    pthread_create(&acceptPthread,NULL,pthread_accept,NULL);
    while(true){
        if(quit){
            close(serv_sock);
            break;
        }
    }
    std::cout<<"成功退出"<<std::endl;
    return 0;

}

int sock;

class Node{
public:
    struct sockaddr_in server;
    int fd;
};

// //创建套接字
// int CreateSock(){
//     int serverSock = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
//     return serverSock;
// }

// //初始化socket元素
// sockaddr_in CreateSockAddrIn(std::string ip,int port){
//     struct sockaddr_in serv_addr;
//     memset(&serv_addr, 0, sizeof(serv_addr));
// 	serv_addr.sin_family = AF_INET;
// 	serv_addr.sin_addr.s_addr = inet_addr(ip.c_str());
// 	serv_addr.sin_port = htons(port);
//     return serv_addr;
// }

void *pthread_send(void* arg){
    std::cout<<"成功创建发送线程"<<std::endl;
    char buffer[7500];
    Node*node = (Node*)arg;
    while(true){
        std::cin.getline(buffer,900);
        std::string s = buffer;
        std::string fin = "quit";
        if(s.find(fin)!=std::string::npos){
            quit=true;
            break;
        }
        if(s.size()>1000){
            std::cout<<"输入过长，请重新输入"<<std::endl;
            continue;
        }
        //现在s和buffer中存储了同样的内容，要把这个内容传送给加密函数加密。
        s = EnryptForTCP(s);//对输入的内容进行DES加密
        memset(buffer,0,7500);
        memcpy(buffer,s.c_str(),s.size());
        int ret = send(node->fd,buffer,7500,0);
        if(ret==-1){
            std::cout<<"发送失败"<<std::endl;
            //std::cout<<errno<<std::endl;
        }else{
            std::cout<<"发送成功"<<std::endl;
        }
        memset(buffer,0,7500);
    }
    return nullptr;
}

void *pthread_recv(void* arg){
    std::cout<<"成功创建接收线程"<<std::endl;
    char buffer[7500];
    while(true){
        int ret = recv(sock,buffer,7500,0);
        if(ret>0){
            std::string s = buffer;
            //std::cout<<s<<std::endl;
            s = DecryptForTCP(s);
            std::cout<<s<<std::endl;
        }
        memset(buffer,0,7500);
        if(quit){
            break;
        }
    }
    return nullptr;
}



int Clientmain(std::string s,int port){
    sock = CreateSock();
    struct sockaddr_in serv_addr = CreateSockAddrIn(s,port);
    std::cout<<"ip、端口绑定完成"<<std::endl;
    //绑定文件描述符和服务器的ip和端口号
    int ret = connect(sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr));
    if(ret==0){
        std::cout<<"成功连接服务端"<<std::endl;
    }
    if(ret==-1){
        std::cout<<"连接服务端失败"<<std::endl;
        close(sock);
        return 0;
    }
    //std::cout<<ret<<std::endl;
    Node*node;
    node->server = serv_addr;
    node->fd = sock;
    pthread_t pthreadSend;
    pthread_t pthreadRecv;
    pthread_create(&pthreadSend,NULL,pthread_send,(void *)node);
    pthread_create(&pthreadRecv,NULL,pthread_recv,(void *)node); 
    while(true){
        if(quit){
            close(sock);
            break;
        }
    }
    std::cout<<"成功退出"<<std::endl;
    return 0;

}

 int main(){
    std::cout<<"Service or Client:C/S:"<<std::endl;
    char c;std::cin>>c;
    if(c=='S'||c=='s'){
        std::cout<<"Use 127.0.0.1 for ip_addr"<<std::endl;
        std::cout<<"Use 6791 for port"<<std::endl;
        Servermain("127.0.0.1",6792);
    }
    if(c=='C'||c=='c'){
        std::string s;
        int port;
        std::cout<<"Input server`s ip"<<std::endl;
        std::cin>>s;
        std::cout<<"Input server`s port"<<std::endl;
        std::cin>>port;
        getchar();
        Clientmain("127.0.0.1",6792);
    }
    while(true){
        if(quit){
            break;
        }
    }
 }