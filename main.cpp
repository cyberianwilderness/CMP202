// Multi-Threaded Bruteforce + lowercase dictionary attack Password Cracker
// CMP202 - Data Structures and Algorithms 2
// Ewan Taylor <1403182@uad.ac.uk>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <ostream>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include "semaphore.h"
#include "userPassword.h"

// Import things we need from the standard library
using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::cin;
using std::condition_variable;
using std::cout;
using std::endl;
using std::fstream;
using std::mutex;
using std::sort;
using std::string;
using std::thread;
using std::unique_lock;
using std::vector;
typedef std::chrono::steady_clock the_clock;

//Global variables
std::atomic<bool> pwd_cracked = false;
std::mutex wait_mutex;
std::atomic<int> finished_threads(0);
mutex pwd_mutex;
condition_variable pwd_crack_cv;

string cracked_password = "";
bool attempt_finished = false;
int maxLength = 8;
// The PasswordStats struct holds various statistics about the password cracking process
struct PasswordStats {
	long long total_time;
	long long median_time;
	long long min_time;
	long long max_time;
};

struct CrackResult {
	string password;
	long long time_taken;
};

void bruteForce(int startChar, int endChar, int maxLength, userPassword& target, Semaphore& sem) 
{
	for (int length = 1; length <= maxLength; ++length) {
		for (int i = 0; i < pow(26, length - 1); ++i) { 
			string attempt(length, 'a');
			int val = i;
			attempt[0] = 'a' + startChar; // first character based on the thread's assigned startChar
			for (int j = length - 1; j >= 1; --j) { 
				attempt[j] += val % 26;
				val /= 26;
			}
			if (target.checkPassword(attempt)) {
				std::unique_lock<std::mutex> lock(pwd_mutex);
				if (!pwd_cracked) {
					cout << "\n[Password has been found via Bruteforce] Password is: " << attempt << std::endl;
					cracked_password = attempt;
					pwd_cracked = true;
					pwd_crack_cv.notify_all();
				}
			}
			if (pwd_cracked) { break; }
		}
		if (pwd_cracked) { break; }
	}
	// Increment finished_threads counter and notify pwd_crack_cv
	std::unique_lock<std::mutex> wait_lock(wait_mutex);
	finished_threads++;
	pwd_crack_cv.notify_all();
}

// Dictionary attack
void passwordCrack(int start_index, int end_index, vector<string>& pwdList, userPassword& target, Semaphore& sem) {
	
	for (int i = start_index; i < end_index && !pwd_cracked; ++i) {
		if (target.checkPassword(pwdList[i])) {
			unique_lock<mutex> lock(pwd_mutex);
			if (!pwd_cracked) {
				cout << "\n[Password has been found via Dictionary attack] Password is: " << pwdList[i] << std::endl;
				cracked_password = pwdList[i];
				pwd_cracked = true;
				pwd_crack_cv.notify_all();
			}
			sem.notify();
			return;
		}
	}
	sem.notify();
}

// The setPwdlist function reads the dictionary file and stores the words in the pwdList vector
void setPwdlist(fstream& file, vector<string>& pwdList) {
	string line;
	cout << "Importing word list..." << endl;
	int wordCount = 0;
	the_clock::time_point start = the_clock::now();
	while (getline(file, line)) 
	{
		pwdList.push_back(line);
		wordCount++;
	}
	the_clock::time_point end = the_clock::now();
	auto time_taken = duration_cast<milliseconds>(end - start).count();
	cout << "Number of words in the password list: " << wordCount << endl << endl; // Output the word count
	cout << "Importing word list complete, took " << time_taken << "ms" << endl << endl;
}

// The createThreads function creates multiple threads for cracking the password
void createThreads(int numThreads, vector<string>& pwdList, userPassword& target) 
{
	cout << "Starting password cracking attempt using " << numThreads << " threads for dictionary attack and 26 threads for brute force attack..." << endl;
	Semaphore sem(numThreads); 
	Semaphore bruteForceSem(26);
	int numPasswords = pwdList.size();
	int passwordsPerThread = numPasswords / numThreads;
	vector<thread> threads; // Store threads in a vector

	for (int i = 0; i < numThreads; ++i) {
		int start_index = i * passwordsPerThread;
		int end_index = (i + 1) * passwordsPerThread;
		if (i == numThreads - 1) { 
			end_index = numPasswords; 
		}
		threads.push_back(thread(passwordCrack, start_index, end_index, std::ref(pwdList), std::ref(target), std::ref(sem))); 	// Create threads for dictionary attack
	}
	for (int startChar = 0; startChar < 26; ++startChar) {
		threads.push_back(thread(bruteForce, startChar, startChar, maxLength, std::ref(target), std::ref(bruteForceSem))); 	// Create threads for brute force attack
	}
	for (int i = 0; i < threads.size(); ++i) {
		threads[i].join(); // Wait for all the threads to finish
	}
}

// The calculatePasswordStats function computes the password cracking statistics
PasswordStats calculatePasswordStats(const vector<std::pair<string, long long>>& results) {
	PasswordStats stats;
	stats.total_time = 0;
	stats.min_time = std::numeric_limits<long long>::max();
	stats.max_time = std::numeric_limits<long long>::min();

	vector<long long> times;
	for (const auto& entry : results)  {
		if (entry.second != -1) {
			stats.total_time += entry.second;
			times.push_back(entry.second);
			stats.min_time = std::min(stats.min_time, entry.second);
			stats.max_time = std::max(stats.max_time, entry.second);
		}
	}
	std::sort(times.begin(), times.end());
	stats.median_time = times.size() % 2 == 0 ? (times[times.size() / 2 - 1] + times[times.size() / 2]) / 2 : times[times.size() / 2];
	return stats;
}

void saveResultsToFile(const std::unordered_map<std::string, long long>& best_times, int threads, int cracked_passwords_count, int not_cracked_count, const vector<std::pair<string, long long>>& results) {
	std::ofstream outFile("results.txt");
	outFile << std::left << std::setw(20) << "Password" << std::setw(20) << "Result" << "Time(ms)" << endl; // Make results legible on text file
	outFile << "------------------------------------------------" << std::endl;

	// Iterate through the best_times and write each entry to the file
	for (const auto& [word, time] : best_times) {
		outFile << std::setw(20) << word;

		bool cracked = false;
		for (const auto& [cracked_password, cracked_time] : results) {
			if (word == cracked_password && cracked_time != -1)	{
				cracked = true;
				outFile << std::setw(20) << "Cracked" << cracked_time;
				break;
			}
		}
		if (!cracked) {
			outFile << std::setw(20) << "Not Cracked" << "Unable to crack";
		}
		outFile << std::endl;
	}



	outFile << "\nThreads used: " << threads << "\n";
	outFile << "Cracked passwords: " << cracked_passwords_count << "\n";
	outFile << "Not cracked passwords: " << not_cracked_count << "\n";
	outFile.close();
}

int main() {
	vector<string> pwdList;
	fstream file;
	userPassword target;
	std::unordered_map<std::string, long long> best_times; // Initialize the best_times map with infinite values

	//cout << "Input the filepath of the Dictionary list: " << endl;
	//cin >> debugFilepath;
	string debugFilepath = "cain.txt"; 	// For Ease of Testing
	file.open(debugFilepath);

	if (!file.is_open()) {
		cout << "Error opening file..." << endl;
		getchar();
		return -1;
	}
	setPwdlist(file, pwdList);
	vector<std::pair<string, long long>> results;
	vector<string> testWords = {												// Predefined list of words to be used for testing
		"bofe", "negf", "yfeg", "yszs", "opef",									// brute force required (4)
		"orchestra", "jazz", "classical", "symphony", "household",				// all in cain dictionary
		"veronika", "xenon", "contrail", "squamatotuberculate", "lazarus",		// all in cain dictionary
		"lfhoi", "greng", "orelo", "nketi", "udrup",							// brute force required (5)
		"soakage", "pereira", "horatio", "gobbler", "raindrop",					// all in cain dictionary
		"ovid", "vaseline", "juniper", "winfield", "gemstone",					// all in cain dictionary
		"saliba", "zadrad", "okocha", "arsene", "arteta",						// brute force required (6)
		"ulster", "quixote", "toreador", "dale", "krypton",						// all in cain dictionary
		"helios", "meridian", "ptarmigan", "ziggurat", "nimrod",				// all in cain dictionary
		"nketiah", "labagje", "crackme", "aavdeff", "zooolk",					// brute force required (7)
		// "AbertayUniAb3rt4y", "CMP202", "1403182", "ass3ssm3nt", "UN1T2",		// these should not be found (contain numbers so brute force won't get it and not in cain
	};
	vector<string> passwordsToCrack;
	bool finished = false;
	int threads;
	int not_cracked_count = 0;
	do 	{
		cout << "Choose an option:" << endl 
			<< "1. Enter the password to crack manually" << endl
			<< "2. Use the predefined list of words for testing" << endl
			<< "3. Exit" << endl;
		int option;
		cin >> option;

		if (option == 1) {
			string password;
			cout << "Enter the password to crack: " << endl;
			cin >> password;
			passwordsToCrack.push_back(password);
		}
		else if (option == 2) {	
			passwordsToCrack = testWords; 
		}
		else if (option == 3) { 
			finished = true;  
			continue; 
		}
		else {
			cout << "Invalid option. Please choose 1,2 or 3\n";
			continue;
		}
		for (const auto& word : passwordsToCrack)  {
			best_times[word] = LLONG_MAX;
		}

		// Request user input for the number of threads
		cout << "Enter the number of threads to use in the dictionary attack: ";
		cin >> threads;

		vector<string> notCrackedWords;		// store passwords that are unable to be cracked

		for (int i = 0; i < 3; ++i) {							// test multiple times to get quickest result
			for (const auto& password : passwordsToCrack) {		// Iterate over the list of passwords to crack
				string lowerPassword = password;
				for (char& c : lowerPassword) {
					c = tolower(c); 	// Make the user password lowercase
				}
				target.setPassword(lowerPassword);
				cout << "Attempting to crack password: " << password << endl;
				
				the_clock::time_point start_total = the_clock::now();
				createThreads(threads, pwdList, target);
				the_clock::time_point end_total = the_clock::now();
				auto time_taken_total = duration_cast<milliseconds>(end_total - start_total).count();
				
				if (time_taken_total < best_times[password]) { 
					best_times[password] = time_taken_total;	// Check if the time taken is less than the current best time & replace if needed
				}
				if (!cracked_password.empty()) {
					cout << "Time taken to crack the password: " << time_taken_total << "ms" << endl;
					results.push_back(std::make_pair(password, time_taken_total));
					cracked_password = ""; // Reset cracked_password
				}
				else {
					cout << "Your password was unable to be cracked!\n";
					notCrackedWords.push_back(password);
					not_cracked_count++;
					results.push_back(std::make_pair(password, -1));
				}
				pwd_cracked = false;
				finished_threads = 0; // Reset the finished_threads counter
			}
		}
		cout << "Do you want to crack another password? (yes/no)" << endl;
		string response;
		cin >> response;
		if (response == "no" || response == "No") {
			finished = true;
		}
		else {
			passwordsToCrack.clear(); // Clear the list of passwords to crack
			finished_threads = 0; // Reset the finished_threads counter
			pwd_cracked = false;
		}
	} while (!finished);

	long long total_time = 0;
	long long min_time = LLONG_MAX;
	long long max_time = LLONG_MIN;
	int cracked_passwords_count = 0;

	for (const auto& entry : results)  {
		if (entry.second != -1) {
			total_time += entry.second;
			cracked_passwords_count++;
			min_time = std::min(min_time, entry.second);
			max_time = std::max(max_time, entry.second);
		}
	}
	if (cracked_passwords_count > 0) {
		double average_time = static_cast<double>(total_time) / cracked_passwords_count;
		cout << "\nTotal time to find " << cracked_passwords_count << " passwords: " << total_time << " ms" << endl;
		cout << "Average time per cracked password: " << average_time << " ms" << endl;
		cout << "Range in cracked passwords: " << max_time - min_time << "ms. Min time (" << min_time << " ms) - Max time ( " << max_time << " ms)" << endl;
	}
	else  { 
		cout << "\nNo passwords were cracked." << endl;	
	}
	saveResultsToFile(best_times, threads, cracked_passwords_count, not_cracked_count, results);

	cout << "Press any key to exit... " << endl;
	cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
	cin.get();
	return 0;
}