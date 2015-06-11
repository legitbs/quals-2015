#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>

#define PASS_LEN 5

#define BASE 1 // comment out for solution

int get_field(char *str);
int send_str(char *str);
void get_pass(const char* var1, char* pass);
void make_printable(char*str);

typedef enum {START, VER_OK, NAME_BASE, NAME_GOOD} State;
State state;

int sock;
char message[1000] , server_reply[2000];

int mutator = 1; // used to modify get_pass()

char curr_name[20];
char nonce[15];
char challenge[6];
int rand_num;

int main(int argc , char *argv[])
{
    if (argc < 2)
    {
        printf("need IP\n");
        return -1;
    }
    char ip_addr[20];
    strncpy(ip_addr, argv[1], 20);

    struct sockaddr_in server;
    
     
    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");
    
    server.sin_addr.s_addr = inet_addr(ip_addr);
    server.sin_family = AF_INET;
    server.sin_port = htons( 17069 );
 
    //Connect to remote server
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("connect failed. Error");
        return 1;
    }

    state = START;

    int started = 0;

    bzero(challenge, 6);
    bzero(nonce, 15);
    
    while(1)
    {
        bzero(message, 1000);
        
        if (started == 0)
        {
            printf("Enter message : ");
            fgets(message, 1000, stdin);
            if (strcmp(message, "hack the world\n") != 0)
            {
                printf("nope...%s\n", message);
                return -1;
            }
            bzero(message, 1000);
            started = 1;
        }

        switch (state)
        {
            case START:
            {
                if (get_field("what version is your client?"))
                {
                    rand_num = (int)nonce[7];

                    // print our version
                    send_str("version 3.11.54\n");
                }
                if (get_field("hello...who is this?"))
                {
                    // print our version
                    state = VER_OK;
                }
                break;
            }
            case VER_OK:
            {
                #ifdef BASE
                send_str("grumpy\n");
                strcpy(curr_name, "grumpy");
                #else
                send_str("duchess\n");
                strcpy(curr_name, "duchess");
                #endif
                get_field("enter user password"); // this is to pass over unneeded prompt from server
                if (get_field("enter user password"))
                {
                    char corr_pass[PASS_LEN+1];
                    bzero (corr_pass, PASS_LEN+1);
                    
                    #ifdef BASE
                    get_pass("grumpy", corr_pass);
                    #else
                    get_pass("duchess", corr_pass);
                    #endif
                    
                    // make corr_pass printable here
                    make_printable(corr_pass);
                    corr_pass[PASS_LEN] = '\0';

                    sprintf(corr_pass, "%s\n", corr_pass);
                    send_str(corr_pass);
                }
                char str[50];
                bzero(str, 50);
                sprintf(str, "hello %s, what would you like to do?", curr_name);
                if (get_field(str))
                {
                    #ifdef BASE
                    state = NAME_BASE;
                    #else
                    state = NAME_GOOD;
                    #endif
                }
                break;
            }
            case NAME_BASE:
            {
                send_str("list users\n");
                get_field("deadwood");
                char str[50];
                bzero(str, 50);
                sprintf(str, "hello %s, what would you like to do?", curr_name);
                if (get_field(str))
                {
                    // enter new command here
                    send_str("print key\n");
                    get_field("the key is:");
                }
                state = START; // TODO: test only, stops output
                break;
            }
            case NAME_GOOD:
            {
                send_str("list users\n");
                get_field("deadwood");
                char str[50];
                bzero(str, 50);
                sprintf(str, "hello %s, what would you like to do?", curr_name);
                if (get_field(str))
                {
                    // enter new command here
                    send_str("print key\n");
                    get_field("challenge:");
                    if (get_field("answer?"))
                    {
                        char answer[6];
                        bzero(answer, 6);
                        mutator = 7;
                        challenge[5] = '\0';
                        get_pass(challenge, answer);

                        mutator = 1;
                        make_printable(answer);
                        answer[5] = '\0';
                        
                        char tmp[6];
                        bzero(tmp, 6);
                        strncpy(tmp, answer, 5);
                        tmp[5] = '\n';
                        send_str(tmp);
                        get_field("the key is:");
                        get_field(str);
                    }
                    
                }
                state = START; // TODO: test only, stops output
                break;
            }
            default:
                state = START;
        }
    }
    close(sock);
    return 0;
}

// listen to socket for string
int get_field(char* str)
{
    // listen for prompt
    if(recv(sock, server_reply, 2000, 0) < 0)
    {
        puts("recv failed");
        exit(-1);
        return 0;
    }
     
    printf("<< %s\n", server_reply);

    if (strstr(server_reply, str) != 0)
    {
        if (strstr(server_reply, "connection ID:") != 0)
        {
            strncpy(nonce, strstr(server_reply, "connection ID: ") + strlen("connection ID: "), 15);
        }
        if (strstr(server_reply, "challenge:") != 0)
        {
            strncpy(challenge, strstr(server_reply, "challenge: ") + strlen("challenge: "), 5);
        }
        bzero(server_reply, 2000);
        return 1;
    }
    bzero(server_reply, 2000);
    return 0;
}

int send_str(char *str)
{
    //Send some data
    int sent = send(sock, str, strlen(str), 0);
    if(sent  < 0)
    {
        puts("Send failed");
        return 0;
    }
    return 1;
}

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
            str[i] = str[i] + 0x20;
        if (str[i] > 0x7E)
        {
            str[i] -= 0x7E;
            str[i] += 0x20;
        }
    }
}