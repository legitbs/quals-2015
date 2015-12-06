#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define X 20
#define Y 20
#define WINCOUNT 5
#define WIN 1
#define LOSE 2
#define INVALID 3
#define OK 4
char board[X][Y];
int SallyX, SparrowY;
int RoomCount;

#define ANGEL 'A'
#define EMPTY ' '
#define EXIT 'E'
#define TARDIS 'T'

#define MOVE_INTERVAL 5

void InitBoard() {
	int x, y;
	int r;
	int PlayerPlaced = 0;
	int AngelCount = 0;
	int side;

	RoomCount++;
	while (AngelCount < 5 || !PlayerPlaced) {
		PlayerPlaced = 0;
		AngelCount = 0;
		for (x = 0; x < X; x++) {
			for (y = 0; y < Y; y++) {
				r = rand() % 40;
				if (r == 0) {
					// place an angel
					board[x][y] = ANGEL;
					AngelCount++;
				} else if (r == 4 && !PlayerPlaced) {
					// Place the player facing one of 4 directions
					r = rand() % 4;
					switch (r) {
						case 0: 
							board[x][y] = 'V';
							break;
						case 1: 
							board[x][y] = '^';
							break;
						case 2: 
							board[x][y] = '<';
							break;
						case 3: 
							board[x][y] = '>';
							break;
					}
					PlayerPlaced = 1;
					SallyX = x;
					SparrowY = y;
				} else {
					board[x][y] = EMPTY;
				}
			}
		}
	}

	if (RoomCount < WINCOUNT) {
		// place the Tardis
		side = rand() % 4;
		switch (side) {
			// top
			case 0:
				do {
					x = rand() % X;
					y = 0;
				} while (x == SallyX && y == SparrowY);
				board[x][y] = EXIT;
				break;
			// left
			case 1:
				do {
					x = 0;
					y = rand() % Y;
				} while (x == SallyX && y == SparrowY);
				board[x][y] = EXIT;
				break;
			// right
			case 2:
				do {
					x = X-1;
					y = rand() % Y;
				} while (x == SallyX && y == SparrowY);
				board[x][y] = EXIT;
				break;
			// bottom
			case 3:
				do {
					x = rand() % X;
					y = Y-1;
				} while (x == SallyX && y == SparrowY);
				board[x][y] = EXIT;
				break;
		}
	} else {
		// place the exit
		do {
			x = rand() % X;
			y = rand() % Y;
		} while (x == SallyX && y == SparrowY);
		board[x][y] = TARDIS;
	}
}

void DisplayBoard() {
	int x, y;
	char line[Y+4];

	printf("   012345678901234567890\n");
	for (y = 0; y < Y; y++) {
		sprintf(line, "%02d ", y);
		for (x = 0; x < X; x++) {
			line[x+3] = board[x][y];
		}
		line[x+3] = '\0';
		printf("%s\n", line);
	}
}

int AcceptMove(char *direction) {
	char line[10];

	while (1) {
		printf("Your move (w,a,s,d,q): ");
		fflush(stdout);
		fgets(line, 9, stdin);
		if (line[1] == '\n') {
			line[1] = '\0';
		}
		if (strlen(line) != 1) {
			printf("Invalid\n");
			return(INVALID);
		}
		switch (line[0]) {
			case 'w':
			case 'a':
			case 's':
			case 'd':
				*direction = line[0];
				return(OK);
			case 'q':
				printf("bye\n");
				exit(0);
		}
	}
}	

int PlayerMove(char direction) {

	switch (direction) {
		case 'w':
			if (SparrowY == 0) {
				printf("Invalid\n");
				return(INVALID);
			}
			if (board[SallyX][SparrowY-1] == ANGEL) {
				return(LOSE);
			}
			if (board[SallyX][SparrowY-1] == EXIT || board[SallyX][SparrowY-1] == TARDIS) {
				return(WIN);
			}
			board[SallyX][SparrowY] = EMPTY;
			board[SallyX][--SparrowY] = 'V';
			return(OK);
		case 'a':
			if (SallyX == 0) {
				printf("Invalid\n");
				return(INVALID);
			}
			if (board[SallyX-1][SparrowY] == ANGEL) {
				return(LOSE);
			}
			if (board[SallyX-1][SparrowY] == EXIT || board[SallyX-1][SparrowY] == TARDIS) {
				return(WIN);
			}
			board[SallyX][SparrowY] = EMPTY;
			board[--SallyX][SparrowY] = '>';
			return(OK);
		case 's':
			if (SparrowY == Y-1) {
				printf("Invalid\n");
				return(INVALID);
			}
			if (board[SallyX][SparrowY+1] == ANGEL) {
				return(LOSE);
			}
			if (board[SallyX][SparrowY+1] == EXIT || board[SallyX][SparrowY+1] == TARDIS) {
				return(WIN);
			}
			board[SallyX][SparrowY] = EMPTY;
			board[SallyX][++SparrowY] = '^';
			return(OK);
		case 'd':
			if (SallyX == X-1) {
				printf("Invalid\n");
				return(INVALID);
			}
			if (board[SallyX+1][SparrowY] == ANGEL) {
				return(LOSE);
			}
			if (board[SallyX+1][SparrowY] == EXIT || board[SallyX+1][SparrowY] == TARDIS) {
				return(WIN);
			}
			board[SallyX][SparrowY] = EMPTY;
			board[++SallyX][SparrowY] = '<';
			return(OK);

		default:
			printf("Invalid\n");
			return(INVALID);

	}
}

int IsPlayer(char c) {

	switch (c) {
		case '^':
		case 'V':
		case '>':
		case '<':
			return(1);
		default:
			return(0);
	}

}

int MoveAngel(int x, int y) {

	if (board[x][y] != ANGEL) {
		return(INVALID);
	}

	if (board[SallyX][SparrowY] == 'V') {
		if (y > SparrowY+1) {
			// angel is far behind, move vertical
			if (board[x][y-1] == EMPTY) {
				board[x][y] = EMPTY;
				board[x][y-1] = ANGEL;
				return(OK);
			}
		}
		if (y > SparrowY) {
			// angel is unseen, move it closer
			if (x == SallyX) {
				if (IsPlayer(board[x][y-1])) {
					return(LOSE);
				} 
			}
			if (x > SallyX && x > 0) {
				if (IsPlayer(board[x-1][y])) {
					return(LOSE);
				} 
				if (board[x-1][y] == EMPTY) {
					board[x][y] = EMPTY;
					board[x-1][y] = ANGEL;
					return(OK);
				}
			}
			if (x < SallyX && x < X-1) {
				if (IsPlayer(board[x+1][y])) {
					return(LOSE);
				} 
				if (board[x+1][y] == EMPTY) {
					board[x][y] = EMPTY;
					board[x+1][y] = ANGEL;
					return(OK);
				}
			}
		}
	} else if (board[SallyX][SparrowY] == '>') {
		if (x > SallyX+1) {
			// angel is far behind, move horizontal
			if (board[x-1][y] == EMPTY) {
				board[x][y] = EMPTY;
				board[x-1][y] = ANGEL;
				return(OK);
			}
		}
		if (x > SallyX) {
			// angel is unseen, move it closer
			if (y == SparrowY) {
				if (IsPlayer(board[x-1][y])) {
					return(LOSE);
				} 
			}
			if (y > SparrowY && y > 0) {
				if (IsPlayer(board[x][y-1])) {
					return(LOSE);
				} 
				if (board[x][y-1] == EMPTY) {
					board[x][y] = EMPTY;
					board[x][y-1] = ANGEL;
					return(OK);
				}
			}
			if (y < SparrowY && y < Y-1) {
				if (IsPlayer(board[x][y+1])) {
					return(LOSE);
				} 
				if (board[x][y+1] == EMPTY) {
					board[x][y] = EMPTY;
					board[x][y+1] = ANGEL;
					return(OK);
				}
			}
		}
	} else if (board[SallyX][SparrowY] == '^') {
		if (y < SparrowY-1) {
			// angel is far behind, move vertical
			if (board[x][y+1] == EMPTY) {
				board[x][y] = EMPTY;
				board[x][y+1] = ANGEL;
				return(OK);
			}
		}
		if (y < SparrowY) {
			// angel is unseen, move it closer
			if (x == SallyX) {
				if (IsPlayer(board[x][y+1])) {
					return(LOSE);
				} 
			}
			if (x > SallyX && x > 0) {
				if (IsPlayer(board[x-1][y])) {
					return(LOSE);
				} 
				if (board[x-1][y] == EMPTY) {
					board[x][y] = EMPTY;
					board[x-1][y] = ANGEL;
					return(OK);
				}
			}
			if (x < SallyX && x < X-1) {
				if (IsPlayer(board[x+1][y])) {
					return(LOSE);
				} 
				if (board[x+1][y] == EMPTY) {
					board[x][y] = EMPTY;
					board[x+1][y] = ANGEL;
					return(OK);
				}
			}
		}
	} else if (board[SallyX][SparrowY] == '<') {
		if (x < SallyX-1) {
			// angel is far behind, move vertical
			if (board[x+1][y] == EMPTY) {
				board[x][y] = EMPTY;
				board[x+1][y] = ANGEL;
				return(OK);
			}
		}
		if (x < SallyX) {
			// angel is unseen, move it closer
			if (y == SparrowY) {
				if (IsPlayer(board[x+1][y])) {
					return(LOSE);
				} 
			}
			if (y > SparrowY && y > 0) {
				if (IsPlayer(board[x][y-1])) {
					return(LOSE);
				} 
				if (board[x][y-1] == EMPTY) {
					board[x][y] = EMPTY;
					board[x][y-1] = ANGEL;
					return(OK);
				}
			}
			if (y < SparrowY && y < Y-1) {
				if (IsPlayer(board[x][y+1])) {
					return(LOSE);
				} 
				if (board[x][y+1] == EMPTY) {
					board[x][y] = EMPTY;
					board[x][y+1] = ANGEL;
					return(OK);
				}
			}
		}
	}

	return(OK);
}

int Radiate(void) {
	int x,y;

	// radiate up and down from SallyX,SparrowY
	if (SparrowY != 0) {
		for (y = SparrowY-1; y >= 0; y--) {
			if (MoveAngel(SallyX,y) == LOSE) {
				return(LOSE);
			}
		}
	}
	if (SparrowY != Y-1) {
		for (y = SparrowY+1; y < Y; y++) {
			if (MoveAngel(SallyX,y) == LOSE) {
				return(LOSE);
			}
		}
	}

	if (SallyX != 0) {
		for (x = SallyX-1; x >= 0; x--) {
			for (y = SparrowY; y >= 0; y--) {
				if (MoveAngel(x,y) == LOSE) {
					return(LOSE);
				}
			}
			if (SparrowY != Y-1) {
				for (y = SparrowY+1; y < Y; y++) {
					if (MoveAngel(x,y) == LOSE) {
						return(LOSE);
					}
				}
			}
		}
	}

	if (SallyX != X-1) {
		for (x = SallyX+1; x < X; x++) {
			for (y = SparrowY; y >= 0; y--) {
				if (MoveAngel(x,y) == LOSE) {
					return(LOSE);
				}
			}
			if (SparrowY != Y-1) {
				for (y = SparrowY+1; y < Y; y++) {
					if (MoveAngel(x,y) == LOSE) {
						return(LOSE);
					}
				}
			}
		}
	}
			
}

void TooSlow(int signum) {

	printf("Too slow!\n");
	exit(0);

}

void AngelGame(void) {
	char direction;
	int result;

        signal(SIGALRM, TooSlow);

	srand(time(NULL));
	RoomCount = 0;
	InitBoard();

	printf("You(^V<>) must find your way to the TARDIS(T) by avoiding the angels(A).\n");
	printf("Go through the exits(E) to get to the next room and continue your search.\n");
	printf("But, most importantly, don't blink!\n");
	DisplayBoard();

	while (RoomCount <= WINCOUNT) {
        	alarm(MOVE_INTERVAL);
		if (AcceptMove(&direction) == OK) {
			result = PlayerMove(direction);
			if (result == WIN) {
				if (RoomCount < WINCOUNT-1) {
					printf("You escaped one room, only to find...\n");
				} else if (RoomCount < WINCOUNT) {
					printf("Finally...the TARDIS!\n");
				} else {
					break;
				}
				InitBoard();
				DisplayBoard();
				continue;
			} else if (result == LOSE) {
				printf("Enjoy 1960...\n");
				exit(0);
			}
		}

		if (Radiate() == LOSE) {
			printf("Enjoy 1960...\n");
			exit(0);
		}
		DisplayBoard();
	}

	return;
}
