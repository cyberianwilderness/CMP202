// this code was tried to get the brute force more effectively but led to memory issues.

/*
void bruteForceRecursive(string& attempt, int length, int position, userPassword& target)
{
	if (pwd_cracked) { return; }

	if (position == length) {
		unique_lock<mutex> lock(attempt_mutex);
		if (target.checkPassword(attempt)) {
			unique_lock<mutex> pwd_lock(pwd_mutex);
			if (!pwd_cracked) {
				cout << "\n[Password has been found via Bruteforce] Password is: " << attempt << endl;
				cracked_password = attempt;
				pwd_cracked = true;
				pwd_crack_cv.notify_all();
			}
		}
		return;
	}
	for (char c = 'a'; c <= 'z'; ++c) {
		attempt[position] = c;
		bruteForceRecursive(attempt, length, position + 1, target);
	}
}

bool incrementString(string& attempt) {
	int pos = attempt.size() - 1;
	while (pos >= 0) {
		if (attempt[pos] == 'z') {
			attempt[pos] = 'a';
			pos--;
		}
		else {
			attempt[pos]++;
			return true;
		}
	}
	return false;
}

void bruteForceThread(int startChar, int endChar, int maxLength, userPassword& target)
{
	for (int length = 1; length <= maxLength; ++length) {
		for (int i = 0; i < pow(26, length); ++i) {
			string attempt(length, 'a');
			int val = i;
			for (int j = length - 1; j >= 0; --j) {
				attempt[j] += val % 26;
				val /= 26;
			}
			if (attempt[0] >= ('a' + startChar) && attempt[0] <= ('a' + endChar)) {
				bruteForceRecursive(attempt, length, 0, target);
			}
			if (pwd_cracked) { break; }
		}
		if (pwd_cracked) { break; }
	}
}
*/