// Multi-Threaded password cracker implemented by Jonah McElfatrick
// Uses a mixture of dictionary attack and brute force methods to attempt to crack the inputted hash
// The hash algorithms compatible with this algorithm are MD5, SHA224, SHA256, SHA384 and SHA512
#include <iostream>
#include <string>
#include <fstream>
#include <thread>
#include <mutex>
#include <vector>
#include "md5.h" // NOT MY OWN WORK, THIS FILE WAS TAKEN FROM http://www.zedwood.com/article/cpp-md5-function
#include "sha224.h" // NOT MY OWN WORK, THIS FILE WAS TAKEN FROM http://www.zedwood.com/article/cpp-sha224-function
#include "sha256.h" // NOT MY OWN WORK, THIS FILE WAS TAKEN FROM http://www.zedwood.com/article/cpp-sha256-function
#include "sha384.h" // NOT MY OWN WORK, THIS FILE WAS TAKEN FROM http://www.zedwood.com/article/cpp-sha384-function
#include "sha512.h" // NOT MY OWN WORK, THIS FILE WAS TAKEN FROM http://www.zedwood.com/article/cpp-sha512-function

using namespace std;

// Import clock
using std::chrono::duration_cast;
using std::chrono::milliseconds;

// Define the alias "the_clock" for the clock type we're going to use.
typedef std::chrono::steady_clock the_clock;

// Mutex for when calculating the hash
mutex hash_mutex;

// Mutex for when displaying the current attempted password
mutex cout_mutex;

// Counter condition variable to count the number of attempts been carried out
condition_variable counter_cv;
mutex counter_mutex;
bool counter_bool;

// Bool to identify if the password has been found or not
bool done = false;

// String for the found password
string FoundPassword;

// Counter
int counter = 0;

// Method of found
string method;

// Used method
string hashMethod;

// Uppercase letters array
const char CapitaLetters[26] =
{
	'A', 'B', 'C', 'D', 'E', 'F', 'G',
	'H', 'I', 'J', 'K', 'L', 'M', 'N',
	'O', 'P', 'Q', 'R', 'S', 'T', 'U',
	'V', 'W', 'X', 'Y', 'Z'
};

// Lowercase letters array
const char LowerCaseLetters[26] =
{
	'a', 'b', 'c', 'd', 'e', 'f', 'g',
	'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u',
	'v', 'w', 'x', 'y', 'z'
};

// Symbols array
const char Symbols[22] =
{
	'!','£','$','%','^','&','*','(',')'
	,'@','~','#','|','?','¬','`','{',
	'}','[',']',';',':'
};

// Numbers array
const char Numbers[10] =
{
	'1','2','3','4','5','6','7','8','9','0'
};

// Takes each line in the word file, hashes it then compares it to the entered hash to see if they match
// If they match then the password has been found, else it continues on till the end of the file
void dictionaryAttack(string filename, string inputHash, int hashChoice, int display) {
	// Variable for the contents of the file
	string contents;

	// Opens the text file for reading
	ifstream file(filename, ios_base::binary);

	// Check to see if the file was successfully opened
	if (!file.good()) {
		cout << "Unable to open file: " << filename << endl;
		system("pause");
	}
	else {
		// Takes each line in the text file and hashes the contents, then compares it to the entered hash
		while (file >> contents && !done) {
			// Notify the counter condition variable to allow the addition of another attempt to the counter variable
			counter_bool = true;
			counter_cv.notify_one();

			// Check to see if the user wants to print out current password being attempted
			// Mutex's used to allow for a clean output on which password is being attempted
			if (display == 1) {
				cout_mutex.lock();
				cout << contents << endl;
				cout_mutex.unlock();
			}
			
			// Initialise hash variable to store the hashed attempted password
			string hash = "";

			if (hashChoice == 1 || hashChoice == 2) {
				// Hash the password using MD5
				hash_mutex.lock();
				hash = md5(contents);
				hash_mutex.unlock();

				// Checks to see if the current hashed attempted password is equal to the inputted hash in MD5
				if (hash == inputHash) {
					hashMethod = "MD5";
					cout << endl << "Hash: " << hash << endl;
					cout_mutex.lock();
					done = true;
					FoundPassword = contents;
					method = "Dictionary";
					cout_mutex.unlock();
				}
			}

			if (hashChoice == 1 || hashChoice == 3) {
				// Hash the password using sha224
				hash_mutex.lock();
				hash = sha224(contents);
				hash_mutex.unlock();

				// Checks to see if the current hashed attempted password is equal to the inputted hash in SHA224
				if (hash == inputHash) {
					hashMethod = "SHA-224";
					cout << endl << "Hash: " << hash << endl;
					cout_mutex.lock();
					done = true;
					FoundPassword = contents;
					method = "Dictionary";
					cout_mutex.unlock();
				}
			}

			if (hashChoice == 1 || hashChoice == 4) {
				// Hash the password using sha256
				hash_mutex.lock();
				hash = sha256(contents);
				hash_mutex.unlock();

				// Checks to see if the current hashed attempted password is equal to the inputted hash in SHA256
				if (hash == inputHash) {
					hashMethod = "SHA-256";
					cout << endl << "Hash: " << hash << endl;
					cout_mutex.lock();
					done = true;
					FoundPassword = contents;
					method = "Dictionary";
					cout_mutex.unlock();
				}
			}

			if (hashChoice == 1 || hashChoice == 5) {
				// Hash the password using sha384
				hash_mutex.lock();
				hash = sha384(contents);
				hash_mutex.unlock();

				// Checks to see if the current hashed attempted password is equal to the inputted hash in SHA384
				if (hash == inputHash) {
					hashMethod = "SHA-384";
					cout << endl << "Hash: " << hash << endl;
					cout_mutex.lock();
					done = true;
					FoundPassword = contents;
					method = "Dictionary";
					cout_mutex.unlock();
				}
			}

			if (hashChoice == 1 || hashChoice == 6) {
				// Hash the password using sha512
				hash_mutex.lock();
				hash = sha512(contents);
				hash_mutex.unlock();

				// Checks to see if the current hashed attempted password is equal to the inputted hash in SHA512
				if (hash == inputHash) {
					hashMethod = "SHA-512";
					cout << endl << "Hash: " << hash << endl;
					cout_mutex.lock();
					done = true;
					FoundPassword = contents;
					method = "Dictionary";
					cout_mutex.unlock();
				}
			}
		}
	}
	// Closes the input textfile
	file.close();
	return;
}

// Tries every iteration or possibility from lowercase letters, uppercase letters, numbers and symbols. Hashes these itterations and then compares them to the entered hash value
// If the calculated hash is equal to the entered hash then the password has been found, else it continues on till the end of the possible itterations
// For each thread running this function they are calculating it for different lengths, for example thread one will calculate for a password string length of 1
// thread two will calculate for a password string length of 2, thread three will calculate for a password string length of 3 and so on.
void bruteForce(int stringlength, string s, string inputHash, int hashChoice, int display) {
	// Check to see if the password has been found, if so will start the return process on all iterations of the function
	if (done) return;

	string pwordattempt;

	// Checks to see if the attempted password length for the thread has been reached to then check if the attempted password is equal to the actual password
	if (stringlength == 0)
	{
		// Notify the counter condition variable to allow the addition of another attempt to the counter variable
		counter_bool = true;
		counter_cv.notify_one();

		// Check to see if the user wants to print out current password being attempted
		// Mutex's used to allow for a clean output on which password is being attempted
		if (display == 1) {
			cout_mutex.lock();
			cout << s << endl;
			cout_mutex.unlock();
		}

		// Initialise hash variable to store the hashed attempted password
		string hash = "";

		if (hashChoice == 1 || hashChoice == 2) {
			// Hash the password using MD5
			hash_mutex.lock();
			hash = md5(s);
			hash_mutex.unlock();

			// Checks to see if the current hashed attempted password is equal to the inputted hash in MD5
			if (hash == inputHash) {
				hashMethod = "MD5";
				cout << endl << "Hash: " << hash << endl;
				cout_mutex.lock();
				done = true;
				FoundPassword = s;
				method = "Brute Force";
				cout_mutex.unlock();
			}
		}

		if (hashChoice == 1 || hashChoice == 3) {
			// Hash the password using sha224
			hash_mutex.lock();
			hash = sha224(s);
			hash_mutex.unlock();

			// Checks to see if the current hashed attempted password is equal to the inputted hash in SHA224
			if (hash == inputHash) {
				hashMethod = "SHA-224";
				cout << endl << "Hash: " << hash << endl;
				cout_mutex.lock();
				done = true;
				FoundPassword = s;
				method = "Brute Force";
				cout_mutex.unlock();
			}
		}

		if (hashChoice == 1 || hashChoice == 4) {
			// Hash the password using sha256
			hash_mutex.lock();
			hash = sha256(s);
			hash_mutex.unlock();

			// Checks to see if the current hashed attempted password is equal to the inputted hash in SHA256
			if (hash == inputHash) {
				hashMethod = "SHA-256";
				cout << endl << "Hash: " << hash << endl;
				cout_mutex.lock();
				done = true;
				FoundPassword = s;
				method = "Brute Force";
				cout_mutex.unlock();
			}
		}

		if (hashChoice == 1 || hashChoice == 5) {
			// Hash the password using sha384
			hash_mutex.lock();
			hash = sha384(s);
			hash_mutex.unlock();

			// Checks to see if the current hashed attempted password is equal to the inputted hash in SHA384
			if (hash == inputHash) {
				hashMethod = "SHA-384";
				cout << endl << "Hash: " << hash << endl;
				cout_mutex.lock();
				done = true;
				FoundPassword = s;
				method = "Brute Force";
				cout_mutex.unlock();
			}
		}

		if (hashChoice == 1 || hashChoice == 6) {
			// Hash the password using sha512
			hash_mutex.lock();
			hash = sha512(s);
			hash_mutex.unlock();

			// Checks to see if the current hashed attempted password is equal to the inputted hash in SHA512
			if (hash == inputHash) {
				hashMethod = "SHA-512";
				cout << endl << "Hash: " << hash << endl;
				cout_mutex.lock();
				done = true;
				FoundPassword = s;
				method = "Brute Force";
				cout_mutex.unlock();
			}
		}
		return;
	}

	for (int i = 0; i < 26 && !done; i++) // iterate through alphabet
	{
		// Append new character onto the string
		// Recursively call function again untill string has reached its length
		// Loop for lowercase letters
		pwordattempt = s + LowerCaseLetters[i];
		bruteForce(stringlength - 1, pwordattempt, inputHash, hashChoice, display);
	}

	// Loop for capital letters
	for (int j = 0; j < 26 && !done; j++) {
		pwordattempt = s + CapitaLetters[j];
		bruteForce(stringlength - 1, pwordattempt, inputHash, hashChoice, display);
	}

	// Loop for symbols
	for (int x = 0; x < 22 && !done; x++) {
		pwordattempt = s + Symbols[x];
		bruteForce(stringlength - 1, pwordattempt, inputHash, hashChoice, display);
	}

	// Loop for numbers
	for (int y = 0; y < 10 && !done; y++) {
		pwordattempt = s + Numbers[y];
		bruteForce(stringlength - 1, pwordattempt, inputHash, hashChoice, display);
	}
}

void randomStringAttack(string filename, string inputHash, int hashChoice, int display) {
	// Variable for the contents of the file and then the attempted password
	string contents;

	//Vector to store the words from the file
	vector<string> words;

	// Opens the text file for reading
	ifstream file(filename, ios_base::binary);

	// Check to see if the file was successfully opened
	if (!file.good()) {
		cout << "Unable to open file: " << filename << endl;
		system("pause");
	}
	else {
		// Read in the entire contents of the file into the words vector
		while (file >> contents) {
			words.push_back(contents);
		}
		// Closes the input textfile
		file.close();
		// Takes each line in the text file and hashes the contents, then compares it to the entered hash
		while (!done){
			for (int i = 0; i < words.size(); i++) {
				for (int j = 1; j < words.size(); j++) {
					for (int k = 2; k < words.size(); k++) {
						if (done) {
							return;
						}
						//cout << words[i] << '-' << words[j] << '-' << words[k];
						contents = words[i] + '-' + words[j] + '-' + words[k];

						// Notify the counter condition variable to allow the addition of another attempt to the counter variable
						counter_bool = true;
						counter_cv.notify_one();

						// Check to see if the user wants to print out current password being attempted
						// Mutex's used to allow for a clean output on which password is being attempted
						if (display == 1) {
							cout_mutex.lock();
							cout << contents << endl;
							cout_mutex.unlock();
						}

						// Initialise hash variable to store the hashed attempted password
						string hash = "";

						if (hashChoice == 1 || hashChoice == 2) {
							// Hash the password using MD5
							hash_mutex.lock();
							hash = md5(contents);
							hash_mutex.unlock();

							// Checks to see if the current hashed attempted password is equal to the inputted hash in MD5
							if (hash == inputHash) {
								hashMethod = "MD5";
								cout << endl << "Hash: " << hash << endl;
								cout_mutex.lock();
								done = true;
								FoundPassword = contents;
								method = "Random String";
								cout_mutex.unlock();
							}
						}

						if (hashChoice == 1 || hashChoice == 3) {
							// Hash the password using sha224
							hash_mutex.lock();
							hash = sha224(contents);
							hash_mutex.unlock();

							// Checks to see if the current hashed attempted password is equal to the inputted hash in SHA224
							if (hash == inputHash) {
								hashMethod = "SHA-224";
								cout << endl << "Hash: " << hash << endl;
								cout_mutex.lock();
								done = true;
								FoundPassword = contents;
								method = "Random String";
								cout_mutex.unlock();
							}
						}

						if (hashChoice == 1 || hashChoice == 4) {
							// Hash the password using sha256
							hash_mutex.lock();
							hash = sha256(contents);
							hash_mutex.unlock();

							// Checks to see if the current hashed attempted password is equal to the inputted hash in SHA256
							if (hash == inputHash) {
								hashMethod = "SHA-256";
								cout << endl << "Hash: " << hash << endl;
								cout_mutex.lock();
								done = true;
								FoundPassword = contents;
								method = "Random String";
								cout_mutex.unlock();
							}
						}

						if (hashChoice == 1 || hashChoice == 5) {
							// Hash the password using sha384
							hash_mutex.lock();
							hash = sha384(contents);
							hash_mutex.unlock();

							// Checks to see if the current hashed attempted password is equal to the inputted hash in SHA384
							if (hash == inputHash) {
								hashMethod = "SHA-384";
								cout << endl << "Hash: " << hash << endl;
								cout_mutex.lock();
								done = true;
								FoundPassword = contents;
								method = "Random String";
								cout_mutex.unlock();
							}
						}

						if (hashChoice == 1 || hashChoice == 6) {
							// Hash the password using sha512
							hash_mutex.lock();
							hash = sha512(contents);
							hash_mutex.unlock();

							// Checks to see if the current hashed attempted password is equal to the inputted hash in SHA512
							if (hash == inputHash) {
								hashMethod = "SHA-512";
								cout << endl << "Hash: " << hash << endl;
								cout_mutex.lock();
								done = true;
								FoundPassword = contents;
								method = "Random String";
								cout_mutex.unlock();
							}
						}
					}
				}
			}
			
		}
	}
	
	return;
}

// Simple function to check if an integer is within a certain range
int validateInt(int min, int max, int choice) {
	while (choice < min || choice > max) {
		cout << "Invalid Input" << endl;
		cout << "Please enter a value from the range above: " << endl << ">> ";
		cin >> choice;
		cout << endl;
	}
	return choice;
}

// Validate the input of the receiveDisplayChoice function
int validateDisplayInput(string userInput) {
	int choice;
	// Check to see if the user
	if (userInput == "y" || userInput == "Y") {
		choice = 1;
	}
	else if (userInput == "n" || userInput == "N") {
		choice = 0;
	}
	else {
		cout << "Please enter a valid input" << endl;
		choice = 2;
	}

	return choice;
}

// Validate the file format entered by the user
int validateFileFormat(string filename) {
	int n = 4;
	int validationCheck = 0;
	if (n > filename.length()) {
		cout << "Filename not long enough" << endl;
	}
	else if ((filename.substr(filename.length() - n) != ".txt")) {
		cout << "Invalid format. Please enter the name of a txt file" << endl;
	}
	else {
		validationCheck = 1;
	}
	return validationCheck;
}

// Receive the choice of which hashing algorithm the password was hashed with
int ReceiveChoiceInput() {
	int choice;
	cout << "Would you like to attempt to crack:" << endl << "1: All Hashes supported" << endl << "2: Certain Hash" << endl << ">> ";
	cin >> choice;
	cout << endl;
	validateInt(1, 2, choice);
	if (choice == 2) {
		cout << "Please enter the type of hash you are wanting to crack" << endl << "2: MD5" << endl << "3: SHA-224" << endl << "4: SHA-256" << endl << "5: SHA-384" << endl << "6: SHA-512" << endl << ">> ";
		cin >> choice;
		cout << endl;
		validateInt(2, 6, choice);
	}
	return choice;
}

// Receive the hash that is trying to be cracked
string ReceiveHashInput() {
	string hash;
	cout << "Please enter the hash you would like to crack: " << endl << ">> ";
	cin >> hash;
	cout << endl;
	return hash;
}

// Receive the filename for the wordlist used in the dictionary attack
string ReceiveFilename(int attackType) {
	string filename;
	int validationCheck = 0;
	while (validationCheck == 0) {
		if (attackType == 0) {
			cout << "Type 'y' to use the default wordlist.txt file or enter the name of your custom file: " << endl << ">> ";
			cin >> filename;
			if (filename == "y" || filename == "Y") {
				filename = "wordlist.txt";
				validationCheck = 1;
			}
			// Validate the user entry matches the required format
			validationCheck = validateFileFormat(filename);
		}
		else {
			cout << "Type 'y' to use the default dictionary.txt file or enter the name of your custom file: " << endl << ">> ";
			cin >> filename;
			if (filename == "y" || filename == "Y") {
				filename = "dictionary.txt";
			}
			// Validate the user entry matches the required format
			validationCheck = validateFileFormat(filename);
		}
	}
	cout << endl;
	return filename;
}

// Function for receiving the number of threads that will run depending on how many characters the user wants to try and crack the password for
int ReceiveThreads() {
	int threadNumber;
	int choice;
	// Gives the user the choice to use the maximum number of threads available by the computer's CPU
	// Or to use a specified number of threads
	cout << "Please select from the following: " << endl << "1: Specify number of threads" << endl << "2: Detect Maximum threads" << endl << ">> ";
	cin >> choice;
	cout << endl;
	// Validate choice is one from the list above
	validateInt(1, 2, choice);
	
	if (choice == 1) {
		cout << "Please enter the number of characters you would like to try to crack: " << endl << ">> ";
		cin >> threadNumber;
		cout << endl;

		// Validate the input is no more than 6 characters long
		validateInt(1, 10, threadNumber);

		// Returning threadNumber + 2 as there is 2 threads needed extra, one for the dictionary
		// attack and one to run the counter function to count the number of times a attempt has been made to crack the password
		threadNumber += 2;
	}
	else {
		threadNumber = thread::hardware_concurrency();
	}

	return threadNumber;
}

// Function to receive the choice to display the current attempted password
int receiveDisplayChoice() {
	int choice = 2;
	string userInput;

	while (choice > 1 || choice < 0) {
		cout << "Would you like to view all attempted password? (Y/N)" << endl << "Please note this will increase the time taken to crack the password drastically" << endl << ">> ";
		cin >> userInput;
		choice = validateDisplayInput(userInput);
	}
	return choice;
}

int ReceiveMethodChoice() {
	int choice;
	cout << "Would you like to:" << endl << "1: Hash an input? " << endl << "2: Attempt to crack a hash? " << endl << ">> ";
	cin >> choice;
	cout << endl;
	choice = validateInt(1, 2, choice);
	return choice;
}

// Function to record the number of attempts that have been made to crack the entered hash
void numberCounter() {
	while (!done)
	{
		unique_lock<mutex> mylock(counter_mutex);
		while (!done && counter_bool == false) {
			counter_cv.wait(mylock);
		}
		if (done)
			return;
		counter += 1;
		counter_bool = false;
	}
	return;
}

// Function to hash the users input and return the hashed value to the screen
void hashFunction() {
	// Initialise variables for selecting the hash choice, the string to be hashed and the calculated hash
	int hashChoice;
	string stringToHash;
	string hash;

	cout << "What hash would you like to use" << endl << "1: MD5" << endl << "2: SHA-224" << endl << "3: SHA-256" << endl << "4: SHA-384" << endl << "5: SHA-512" << endl << ">> ";
	cin >> hashChoice;
	cout << endl;
	hashChoice = validateInt(1, 5, hashChoice);
	cout << "Please enter the string you would like to hash" << endl << ">> ";
	cin >> stringToHash;
	cout << endl;

	switch (hashChoice)
	{
	case 1: hash = md5(stringToHash); break;
	case 2: hash = sha224(stringToHash); break;
	case 3: hash = sha256(stringToHash); break;
	case 4: hash = sha384(stringToHash); break;
	case 5: hash = sha512(stringToHash); break;
	default:
		break;
	}

	cout << "String: " << stringToHash << endl << "Produced Hash: " << hash << endl;
	return;
}

int main()
{
	// Initialise variable for storing the filename of the wordlist being used for the dictionary attack
	string dictionaryFilename;
	
	// Initialise variable for storing the filename of the wordlist being used for the random string attack
	string stringFilename;

	// Choice of which hash is being used
	int hashChoice = 0;

	// The inputted hash that is the target goal to crack
	string inputHash = "";

	// Number of attemtps to crack the password
	int attempts;

	// Length of the string being attempted as the password
	int stringlength = 1;
	
	// Number of threads that are being initiated 
	int threadNumber;

	// Choice to display attempted passwords or not
	int display;

	// Choice of hash or crack
	int methodChoice;

	// Receive the choice to hash an input or crack a hash
	methodChoice = ReceiveMethodChoice();

	// Check to see what method has been chosen
	if (methodChoice == 1) {
		hashFunction();
	}
	else {
		// Receive the which hashing algorithm is being used
		hashChoice = ReceiveChoiceInput();

		// Receive the hash that is being broken
		inputHash = ReceiveHashInput();

		// Receive the name of the text file that is being used in the dictionary attack
		dictionaryFilename = ReceiveFilename(0);

		// Receive the name of the text file that is being used in the string attack
		stringFilename = ReceiveFilename(1);

		// Receive the choice to display the attempted passwords or not
		display = receiveDisplayChoice();

		// Receive the number of threads to be initiated
		threadNumber = ReceiveThreads();

		cout << "Initialising password crack...";

		// Start the clock 
		the_clock::time_point start = the_clock::now();

		// Initialise vector of threads
		vector<thread> tvector = {};

		// Initialise the thread to run the counter loop to count the number of attempts to crack the password
		tvector.push_back(thread(numberCounter));

		// Initialising threads each cracking the password for a different length
		while (stringlength < (threadNumber - 2)) {
			tvector.push_back(thread(bruteForce, stringlength, "", inputHash, hashChoice, display));
			stringlength++;
		}

		//Initialise thread for Dictionary attack
		tvector.push_back(thread(dictionaryAttack, dictionaryFilename, inputHash, hashChoice, display));

		//Initialise thread for String attack
		tvector.push_back(thread(randomStringAttack, stringFilename, inputHash, hashChoice, display));

		// Join all working threads 
		for (int i = 1; i < threadNumber; i++) {
			tvector[i].join();
		}

		// Display the cracked password if found and the number of tries to crack it
		if (done) {
			cout << "Cracked Password: " << FoundPassword << endl;
			cout << "Number of attempts to crack the password: " << counter << endl;
		}
		//Display password not found
		else {
			cout << "Password not found" << endl;
		}
		the_clock::time_point end = the_clock::now();
		// End the clock

		// Compute and display the difference between the start and end times in milliseconds
		auto time_taken = duration_cast<milliseconds>(end - start).count();
		cout << "Cracking the password took " << time_taken << " ms. " << "It was using the " << hashMethod << " hash method. " << "It was found using the " << method << " attack." << endl;

		// Notify and join the thread that is running the counter loop to count the number of password attempts
		counter_cv.notify_one();
		(tvector.front()).join();
	}

	system("pause");
	return 0;
}