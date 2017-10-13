#include "MD5.h"
#include <cassert>
#include <cstring>

namespace MD5 {
	Crypto::Crypto(): a(iA), b(iB), c(iC), d(iD), completed(false), length(0) {}

	void Crypto::reset() {
		completed = false;
		a = iA;
		b = iB;
		c = iC;
		d = iD;
		length = 0;
		left = "";
	}

	void Crypto::checkCompleted() {
		if (completed) {
			throw exception("digest already called, use [reset] to restart crypto");
		}
	}

	void Crypto::work(const Block &block) {
		Reg _a = a, _b = b, _c = c, _d = d;
		for (Reg i = 0; i < 64; i++) {
			Reg g, k;
			switch (i / 16)
			{
				case 0:
					g = (_b & _c) | (~_b & _d);
					k = i % 16;
					break;
				case 1:
					g = (_b & _d) | (_c & ~_d);
					k = (5 * i + 1) % 16;
					break;
				case 2:
					g = _b ^ _c ^ _d;
					k = (3 * i + 5) % 16;
					break;
				case 3:
					g = _c ^ (_b | ~_d);
					k = (7 * i) % 16;
					break;
			}
			_a = rotateLeft(_a + g + Reg(floor(fabs(sin(i + 1) * pow(2, 32)))) + block[k], rotate[i]) + _b;

			Reg tmp = _d;
			_d = _c;
			_c = _b;
			_b = _a;
			_a = tmp;
		}
		a += _a;
		b += _b;
		c += _c;
		d += _d;
	}

	void Crypto::update(const string &data) {
		checkCompleted();
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
		unsigned long long toAppend = length * 8;
		int paddedLen;
		left.append(1, 0b10000000);
		if (left.length() + TAIL_LENGTH_S <= BLOCK_SIZE_S) paddedLen = BLOCK_SIZE_S;
		else paddedLen = BLOCK_SIZE_S * 2;
		left.append(paddedLen - left.length() - TAIL_LENGTH_S, 0);
		left.resize(paddedLen);
		for (int i = 0; i < TAIL_LENGTH_S; i++) {
			left[paddedLen - i - 1] = char(toAppend << (i * 8) >> 56);
		}
	}

	string Crypto::digest(const string &data) {
		checkCompleted();

		left.append(data);
		length += data.length();
		padding();
		update();

		completed = true;

		return toHex(a) + toHex(b) + toHex(c) + toHex(d);
	}

	string Crypto::toHex(Reg r) {
		char buf[9];
		sprintf(buf, "%02X", r << 24 >> 24);
		sprintf(buf + 2, "%02X", r << 16 >> 24);
		sprintf(buf + 4, "%02X", r << 8 >> 24);
		sprintf(buf + 6, "%02X", r >> 24);
		return buf;
	}

	Block Crypto::toBlock(const string &str) {
		assert(str.length() == BLOCK_SIZE_S);
		Block block;
		for (int i = 0; i < BLOCK_LENGTH; i++) {
			block[i] = combine(
				charExtension(str[i * 4]),
				charExtension(str[i * 4 + 1]),
				charExtension(str[i * 4 + 2]),
				charExtension(str[i * 4 + 3])
			);
		}
		return block;
	}

	Reg Crypto::rotateLeft(Reg r, int count) {
		return (r << count) | (r >> (REG_SIZE - count));
	}

	Reg Crypto::charExtension(char c) {
		return Reg(c) & 0b11111111u;
	}
}
