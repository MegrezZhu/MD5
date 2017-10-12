#include "MD5.h"
#include <iostream>

using namespace std;

int main() {
	MD5::Crypto c;
	cout << c.digest("1") << endl;
	system("pause");
}