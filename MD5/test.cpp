#include "MD5.h"
#include <iostream>

using namespace std;

int main() {
	MD5::Crypto c;
	c.update("Hello ");
	cout << c.digest("World!") << endl;
	MD5::Crypto c1;
	cout << c1.digest("The quick brown fox jumps over the lazy dog") << endl;
	system("pause");
}
