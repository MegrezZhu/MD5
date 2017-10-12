#include "MD5.h"
#include <cassert>
#include <cstring>

namespace MD5 {
	Crypto::Crypto(): a(iA), b(iB), c(iC), d(iD), completed(false) {}

	void Crypto::work(const Block &block) {
		for (Reg i = 0; i < 64; i++) {
			Reg g, k;
			switch (i / 64)
			{
				case 0:
					g = (b & c) | (~b & d);
					k = i;
					break;
				case 1:
					g = (b & d) | (c & ~d);
					k = (5 * i + 1) % 16;
					break;
				case 2:
					g = b ^ c ^ d;
					k = (3 * i + 5) % 16;
					break;
				case 3:
					g = c ^ (b | ~d);
					k = (7 * i) % 16;
					break;
			}
			Reg tmp = d;
			d = c;
			c = b;
			b = rotateLeft((a + g + floor(pow(fabs(sin(i + 1)), 32)) + block[g]), rotate[i]) + b;
			a = tmp;
		}
	}

	void Crypto::update(const string &data) {
		left.append(data);
		length += data.length();
		while (left.length() >= BLOCK_SIZE_S) {
			const auto block = toBlock(left.substr(0, BLOCK_SIZE_S));
			work(block);
			left = left.substr(BLOCK_SIZE_S);
		}
	}

	void Crypto::padding() {
		char buf[TAIL_LENGTH_S + 1];
		sprintf(buf, "%ullX", length);
		if (left.length() + TAIL_LENGTH_S + 1 <= BLOCK_SIZE_S) {
			left.append(1, 0b10000000);
			left.append(BLOCK_SIZE_S - left.length() - 1 - TAIL_LENGTH_S, 0);
			left.append(buf);
		}
		else {
			// more padding
			left.append(1, 0x10000000);
			left.append(BLOCK_SIZE_S * 2 - left.length() - 1 - TAIL_LENGTH_S, 0);
			left.append(buf);
		}
	}

	string Crypto::digest(const string &data) {
		left.append(data);
		length += data.length();
		padding();
		update();

		completed = true;

		return toHex(a) + toHex(b) + toHex(c) + toHex(d);
	}

	string Crypto::toHex(Reg r) {
		char buf[5];
		sprintf(buf, "%uX", r);
		return buf;
	}

	Block Crypto::toBlock(const string &str) {
		assert(str.length() == BLOCK_SIZE_S);
		Block block;
		for (int i = 0; i < BLOCK_LENGTH; i++) {
			memcpy(&block[i], str.c_str() + i * REG_SIZE_S, REG_SIZE_S);
		}
		return block;
	}

	Reg Crypto::rotateLeft(Reg r, int count) {
		return (r << count) | (r >> (REG_SIZE - count));
	}
}
