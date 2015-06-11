#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define MIN_LEN 10
#define MAX_LEN 20
#define IN_LEN 10
#define MAX_NAME 15
#define NUM_USERS 8
#define PASS_LEN 5
/*

sudo service inetutils-inetd reload

This is the server.
*/

void parse_packet(char* pkt);
int check_version();
int check_user();
int handle_base_user();
int handle_advanced_user();

const char *users[NUM_USERS];
char nonce[15];

typedef enum {START, VER_OK, NAME_BASE, NAME_GOOD} State;

char name[MAX_NAME];
int rand_num;

void gen_nonce()
{
	int min = 0x20;
	int max = 0x7E;
	srand(time(NULL));

	int i;
	for (i = 0; i < 14; i++)
	{
		int r = max + rand() / (RAND_MAX / (min - max + 1) + 1);
		nonce[i] = (char)r;
	}
	nonce[14] = '\0';
	rand_num = (int)nonce[7];
	printf("connection ID: %s\n", nonce);
}

State state;

int main()
{
	setvbuf(stdout, NULL, _IONBF, 0);

	gen_nonce();

	users[0] = "grumpy";
	users[1] = "mrvito";
	users[2] = "gynophage";
	users[3] = "selir";
	users[4] = "jymbolia";
	users[5] = "sirgoon";
	users[6] = "duchess";
	users[7] = "deadwood";

	state = START;
	char line[IN_LEN];
	while (1)
	{
		switch (state)
		{
			case START:
			{
				bzero(name, MAX_NAME);

				printf("\n\n*** Welcome to the ACME data retrieval service ***\n");
				if (check_version() == 0)
				{
					state = START;
					continue;
				}
				else
				{
					state = VER_OK;
					continue;
				}
				break;
			}
			// version is good, check the user
			case VER_OK:
			{
				
				int ret = check_user();
				if (ret == 0)
				{
					// bad login
					continue;
				}
				else if (ret == 1)
				{
					// base user
					state = NAME_BASE;
				}
				else if (ret == 2)
				{
					// good user
					state = NAME_GOOD;
				}
				break;
			}
			case NAME_BASE: // basic user
			{
				// user can ask for:
				// list of users
				// fake key
				if (handle_base_user() == 0)
				{
					// user exited. reset connection
					state = START;
					continue;
				}
				break;
			}
			case NAME_GOOD: // priveladged user
			{
				if (handle_advanced_user() == 0)
				{
					// user exited. reset connection
					state = START;
					continue;
				}
				break;
			}
			default:
				state = START;
		}
	}
}

int check_version()
{
	int ver_len = 18;
	printf("what version is your client?\n");
	char line[ver_len];
	bzero(line, ver_len);
	fgets(line, ver_len, stdin);
	
	int len = 0;
	len = strnlen(line, ver_len+1);
	if (len != strlen("version 3.11.54") + 1)
	{
		printf("bad version format, your client is broken!\n");
		return 0;
	}

	if (strncmp(line, "version 3.11.54", strlen("version 3.11.54")) == 0)
		return 1;

	printf("old version, please update and reconnect\n");
	return 0;	
}

void left_rot_one(char *arr, int len)
{
	int i;
	char tmp = arr[0];
	for (i = 0; i < len-1; i++)
	{
		arr[i] = arr[i+1];
		arr[i] = arr[i] ^ i;
	}
	arr[i] = tmp;
}

void left_rot(char *arr, int rot_distance, int len)
{
	int i;
	for (i = 0; i < rot_distance; i++)
	{
		left_rot_one(arr, len);
	}
}

int mutator = 1;
void get_pass(const char* var1, char* pass)
{
    int tmp = rand_num % 3;
    tmp += mutator;
    char str[5];
    strncpy(str, &nonce[tmp], 5);

    int i;
    for (i = 0; i < 5; i++)
    {
        pass[i] = str[i] ^ var1[i];
    }
}

void make_printable(char*str)
{
    int i;
    for (i = 0; i < 5; i++)
    {
        if (str[i] < 0x20)
            str[i] = str[i] + 0x20; // move to start of printable
        if (str[i] > 0x7E)
        {
            str[i] -= 0x7E;
            str[i] += 0x20;
        }
    }
}

// what type of user logs in?
int check_user()
{
	printf("hello...who is this?\n");
	char line[MAX_NAME];
	bzero(line, MAX_NAME);
	fgets(line, MAX_NAME-1, stdin);

	int z;
	for (z = 0; z < MAX_NAME-1; z++)
	{
		if (line[z] < 0x20 || line[z] > 0x7E)
			line[z] = '\0';
	}

	int found = 0;
	// check name
	int i;
	for (i = 0; i < NUM_USERS; i++)
	{
		if (strncmp(line, users[i], strlen(users[i])) == 0)
		{
			found = 1;
			printf("enter user password\n");
			char user_pass[PASS_LEN+3];
			char corr_pass[PASS_LEN+3];
			bzero (user_pass, PASS_LEN+3);
			
			get_pass(users[i], corr_pass);
			make_printable(corr_pass);
			fgets(user_pass, PASS_LEN+2, stdin);

			if (strncmp(user_pass, corr_pass, PASS_LEN) == 0)
			{
				strcpy(name, users[i]);
				if (strcmp(line, "duchess") == 0)
					return 2; // admin user
				return 1; // base user
			}
			else
			{
				printf("wrong password, fat fingers\n");
			}
		}
	}
	if (found == 0)
	{
		printf("enter user password\n");
		char user_pass[PASS_LEN+3];
		fgets(user_pass, PASS_LEN+3, stdin);
		sleep(5); // penalize guessing
		printf("wrong password, fat fingers\n");
	}

	return 0;
}

// allows user to:
//  list user accounts
//  upgrade to admin account...nope
int handle_base_user()
{
	char line[MAX_NAME-1];
	
	while (1)
	{
		printf("hello %s, what would you like to do?\n", name);
		bzero(line, MAX_NAME-1);
		fgets(line, MAX_NAME-1, stdin);

		if (strncmp(line, "list users", strlen("list users")) == 0)
		{
			int i;
			for (i = 0; i < NUM_USERS; i++)
			{
				printf("%s\n", users[i]);
			}
			goto skip;
		}
		if (strncmp(line, "print key", strlen("print key")) == 0)
		{
			printf("the key is not accessible from this account. your administrator has been notified.\n");
			return 1;
		}
		if (strncmp(line, "exit", strlen("exit")) == 0)
		{
			state = VER_OK;
			return 1;
		}

		printf("contact your company admin for help\n");
skip:
		continue;
	}


	return 0; // reset connection
}

int verify_admin(const char *name)
{
	// math test to verify admin user

	// print a number
	// expect a given response

	char challenge[6];
	bzero(challenge, 6);
	char answer[6];
	bzero(answer, 6);

	// generate query
	mutator = 4;
	get_pass(name, challenge);
	mutator = 1;
	// 'challenge' now has a randomized 5-char value in it
	make_printable(challenge);
	challenge[5] = '\0';
	printf("challenge: %s\n", challenge);
	
	// generate answer
	mutator = 7;
	get_pass(challenge, answer);
	mutator = 1;

	make_printable(answer);
	answer[5] = '\0';

	char ret[80];
	bzero(ret, 80);
	printf("answer?\n");
	fgets(ret, 80, stdin);

	if (strncmp(answer, ret, 5) == 0)
	{
		return 1; // good answer
	}

	return 0; // bad answer
}

// during login, the user is given a nonce in ascii
// used to generate password (XOR of user name and nonce)

int handle_advanced_user()
{
	char line[MAX_NAME-1];
	
	while (1)
	{
		printf("hello %s, what would you like to do?\n", name);
		bzero(line, MAX_NAME-1);
		fgets(line, MAX_NAME-1, stdin);

		if (strncmp(line, "list users", strlen("list users")) == 0)
		{
			int i;
			for (i = 0; i < NUM_USERS; i++)
			{
				printf("%s\n", users[i]);
			}
			goto skip;
		}
		if (strncmp(line, "print key", strlen("print key")) == 0)
		{
			if (verify_admin(name) != 1)
			{
				state = VER_OK;
				printf("you are not worthy\n");
				return 1;
			}

			FILE *f = fopen("/home/access/keyfile", "r");
			if (f == NULL)
			{
				printf("key file cannot be opened. error...you may complain now.\n");
				continue;
			}
			char str[256];
			bzero(str, 256);
			fread(str, 1, 255, f);
			printf("the key is: %s\n", str);
			fclose(f);
			return 1;
		}
		if (strncmp(line, "exit", strlen("exit")) == 0)
		{
			state = VER_OK;
			return 1;
		}

		printf("error, you should know better\n");
skip:
		continue;
	}


	return 0; // reset connection
}