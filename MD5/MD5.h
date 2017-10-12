#pragma once

#include <string>
#include <cstdint>
#include <array>

namespace MD5 {
	using namespace std;

	typedef uint32_t Reg;

	constexpr Reg combine(Reg a, Reg b, Reg c, Reg d) {
		// return (a << 24) | (b << 16) | (c << 8) | (d);
		return (d << 24) | (c << 16) | (b << 8) | a;
	}

	constexpr Reg iA = 0x67452301, iB = 0xEFCDAB89, iC = 0x98BADCFE, iD = 0x10325476; // initial value for A B C D
	//constexpr Reg 
	//	iA = combine(0x01, 0x23, 0x45, 0x67), 
	//	iB = combine(0x89, 0xAB, 0xCD, 0xEF), 
	//	iC = combine(0xFE, 0xDC, 0xBA, 0x98), 
	//	iD = combine(0x76, 0x54, 0x32, 0x10); // little-endian?
	constexpr int REG_SIZE = 32; 
	constexpr int REG_SIZE_S = REG_SIZE / 8;
	constexpr int BLOCK_SIZE = 512;
	constexpr int BLOCK_SIZE_S = BLOCK_SIZE / 8; // char-wise size
	constexpr int BLOCK_LENGTH = BLOCK_SIZE / REG_SIZE; // # of Regs
	constexpr int TAIL_LENGTH = 64;
	constexpr int TAIL_LENGTH_S = TAIL_LENGTH / 8;

	constexpr int rotate[] = {
		7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
		5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
		4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
		6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
	};

	using Block = array<Reg, BLOCK_SIZE / REG_SIZE>;
	

	class Crypto {
		bool completed;
		Reg a, b, c, d;
		string left;
		unsigned long long length;

		void work(const Block &block);

		void padding();
		void checkCompleted();
		static Block toBlock(const string &str);
		static string toHex(Reg r);
		static Reg rotateLeft(Reg r, int count);
		static Reg charExtension(char c);
	public:
		Crypto();
		void update(const string &data = "");
		string digest(const string &data = "");
		void reset();
	};
}
