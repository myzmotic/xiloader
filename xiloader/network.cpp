/*
===========================================================================

Copyright (c) 2010-2014 Darkstar Dev Teams

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/

This file is part of DarkStar-server source code.

===========================================================================
*/

#include "network.h"

using namespace std;

/* Externals */
extern std::string g_ServerAddress;
extern std::string g_ServerPort;

extern std::string g_Username;
extern std::string g_Password;
extern std::string g_NewPassword;
extern std::string g_ConfirmPassword;
extern std::string g_Email;
extern std::string g_SecurityQuestionAnswer;
extern std::string g_SecurityQuestionID;
extern UINT32 g_SecurityQuestionIDRecieved;

extern char* g_CharacterList;
extern bool g_IsRunning;
extern bool g_Silent;


namespace xiloader
{
    /**
     * @brief Creates a connection on the given port.
     *
     * @param sock      The datasocket object to store information within.
     * @param port      The port to create the connection on.
     *
     * @return True on success, false otherwise.
     */
    bool network::CreateConnection(datasocket* sock, const char* port)
    {
        struct addrinfo hints;
        memset(&hints, 0x00, sizeof(hints));

        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        /* Attempt to get the server information. */
        struct addrinfo* addr = NULL;
        if (getaddrinfo(g_ServerAddress.c_str(), port, &hints, &addr))
        {
            xiloader::console::output(xiloader::color::error, "Failed to obtain remote server information.");
            return 0;
        }

        /* Determine which address is valid to connect.. */
        for (auto ptr = addr; ptr != NULL; ptr->ai_next)
        {
            /* Attempt to create the socket.. */
            sock->s = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (sock->s == INVALID_SOCKET)
            {
                xiloader::console::output(xiloader::color::error, "Failed to create socket.");

                freeaddrinfo(addr);
                return 0;
            }

            /* Attempt to connect to the server.. */
            if (connect(sock->s, ptr->ai_addr, ptr->ai_addrlen) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Failed to connect to server!");

                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return 0;
            }

			if (!g_Silent)
			{
				xiloader::console::output(xiloader::color::info, "Connected to server!");
			}
            break;
        }

        std::string localAddress = "";

        /* Attempt to locate the client address.. */
        char hostname[1024] = { 0 };
        if (gethostname(hostname, sizeof(hostname)) == 0)
        {
            PHOSTENT hostent = NULL;
            if ((hostent = gethostbyname(hostname)) != NULL)
                localAddress = inet_ntoa(*(struct in_addr*)*hostent->h_addr_list);
        }

        sock->LocalAddress = inet_addr(localAddress.c_str());
        sock->ServerAddress = inet_addr(g_ServerAddress.c_str());

        return 1;
    }

    /**
     * @brief Creates a listening server on the given port and protocol.
     *
     * @param sock      The socket object to bind to.
     * @param protocol  The protocol to use on the new listening socket.
     * @param port      The port to bind to listen on.
     *
     * @return True on success, false otherwise.
     */
    bool network::CreateListenServer(SOCKET* sock, int protocol, const char* port)
    {
        struct addrinfo hints;
        memset(&hints, 0x00, sizeof(hints));

        hints.ai_family = AF_INET;
        hints.ai_socktype = protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
        hints.ai_protocol = protocol;
        hints.ai_flags = AI_PASSIVE;

        /* Attempt to resolve the local address.. */
        struct addrinfo* addr = NULL;
        if (getaddrinfo(NULL, port, &hints, &addr))
        {
            xiloader::console::output(xiloader::color::error, "Failed to obtain local address information.");
            return false;
        }

        /* Create the listening socket.. */
        *sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (*sock == INVALID_SOCKET)
        {
            xiloader::console::output(xiloader::color::error, "Failed to create listening socket.");

            freeaddrinfo(addr);
            return false;
        }

        /* Bind to the local address.. */
        if (bind(*sock, addr->ai_addr, (int)addr->ai_addrlen) == SOCKET_ERROR)
        {
            xiloader::console::output(xiloader::color::error, "Failed to bind to listening socket.");

            freeaddrinfo(addr);
            closesocket(*sock);
            *sock = INVALID_SOCKET;
            return false;
        }

        freeaddrinfo(addr);

        /* Attempt to listen for clients if we are using TCP.. */
        if (protocol == IPPROTO_TCP)
        {
            if (listen(*sock, SOMAXCONN) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Failed to listen for connections.");

                closesocket(*sock);
                *sock = INVALID_SOCKET;
                return false;
            }
        }

        return true;
    }


    /**
     * @brief Resolves the given hostname to its long ip format.
     *
     * @param host      The host name to resolve.
     * @param lpOutput  Pointer to a ULONG to store the result.
     *
     * @return True on success, false otherwise.
     */
    bool network::ResolveHostname(const char* host, PULONG lpOutput)
    {
        struct addrinfo hints, *info = 0;
        memset(&hints, 0, sizeof(hints));

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if (getaddrinfo(host, "1000", &hints, &info))
            return false;

        *lpOutput = ((struct sockaddr_in*)info->ai_addr)->sin_addr.S_un.S_addr;

        freeaddrinfo(info);
        return true;
    }

    /**
     * @brief Verifies the players login information; also handles account management.
     *
     * @param sock      The datasocket object with the connection socket.
     *
     * @return True on success, false otherwise.
     */
	bool network::VerifyAccount(datasocket* sock)
	{
		char recvBuffer[1024] = { 0 };
		char sendBuffer[1024] = { 0 };
		std::string input;
		UINT32 q_id_i = 0;
		stringstream q_id_con;

		/* Create connection if required.. */
		if (sock->s == NULL || sock->s == INVALID_SOCKET)
		{
			if (!xiloader::network::CreateConnection(sock, "54231"))
				return false;
		}

		g_Silent = true;

		login_menu:

		xiloader::console::output("==========================================================");
		xiloader::console::output("===============      LOGIN MENU    =======================");
		xiloader::console::output("==========================================================");
		xiloader::console::output("   1.) Login");
		xiloader::console::output("   2.) Create Account");
		xiloader::console::output("   3.) Forgot Password");
		xiloader::console::output("==========================================================");
		printf("\nEnter a selection: ");

		std::cin >> input;
		std::cout << std::endl;

		// Convert to int
		q_id_con = (stringstream)input;
		q_id_i = 0;
		q_id_con >> q_id_i;

		if (q_id_i < 1 || q_id_i > 3)
		{
			xiloader::console::output("Invalid selection..");
			goto login_menu;
		}

		if (input == "1")
		{
			xiloader::console::output("Please enter your login information.");
			std::cout << "\nUsername: ";
			std::cin >> g_Username;
			PromptForPassword();
			std::cout << std::endl;

			sendBuffer[0x82] = LOGIN_ATTEMPT;
			memcpy(sendBuffer + 0x00, g_Username.c_str(), 16);
			memcpy(sendBuffer + 0x10, g_Password.c_str(), 16);
			memcpy(sendBuffer + 0x20, g_Email.c_str(), 32);
		}
		else if (input == "2")
		{

		create_account:
			xiloader::console::output("Please enter your desired login information.");
			std::cout << "\nUsername (3-15 characters): ";
			std::cin >> g_Username;
			std::cout << "Password (6-15 characters): ";
			std::cin >> g_Password;
			std::cout << "Repeat Password           : ";
			std::cin >> input;

			if (input != g_Password)
			{
				xiloader::console::output(xiloader::color::error, "Passwords did not match! Please try again.");
				goto create_account;
			}

			std::cout << "Email: ";
			std::cin >> g_Email;
			std::cout << std::endl;

			std::cout << "Would you like to setup a security question? y/n: ";

			std::cin >> input;

			if (input == "y") 
			{ 
				ChangeSecurityQuestion(); 
			}

			xiloader::console::output(xiloader::color::green, "Please review your information:");
			std::cout << "Username:  " + g_Username;
			std::cout << "\nPassword:  " + g_Password;
			std::cout << "\nEmail:  " + g_Email;

			if (g_SecurityQuestionAnswer != "")
			{
				if (g_SecurityQuestionID == "1")
				{
					std::cout << "\nQuestion: What is your pets name?";
				}
				else if (g_SecurityQuestionID == "2")
				{
					std::cout << "\nQuestion: In what year was your father born?";
				}
				else if (g_SecurityQuestionID == "3")
				{
					std::cout << "\nQuestion: In what town or city was your first full time job?";
				}
				else if (g_SecurityQuestionID == "4")
				{
					std::cout << "\nQuestion: What are the last five digits of your drivers licence number?";
				}
				else if (g_SecurityQuestionID == "5")
				{
					std::cout << "\nQuestion: What is your spouse or partners mothers maiden name?";
				}

				std::cout << "\nAnswer:  " + g_SecurityQuestionAnswer;
			}
			else
			{
				xiloader::console::output(xiloader::color::info, " ");
				xiloader::console::output(xiloader::color::info, "** Opted out of security question.");
				xiloader::console::output(xiloader::color::info, "** You will not be able to recover your password without one set.");
			    xiloader::console::output(xiloader::color::info, "** You may set one at anytime after account has been created.\n");
			}

			std::cout << "\nIs this correct? y/n";

			std::cin >> input;
			std::cout << std::endl;

			if (input == "y")
			{
				sendBuffer[0x82] = LOGIN_CREATE;
				memcpy(sendBuffer + 0x00, g_Username.c_str(), 16);
				memcpy(sendBuffer + 0x10, g_Password.c_str(), 16);
				memcpy(sendBuffer + 0x20, g_Email.c_str(), 32);
				memcpy(sendBuffer + 0x40, g_SecurityQuestionAnswer.c_str(), 64);
				memcpy(sendBuffer + 0x80, g_SecurityQuestionID.c_str(), 2);
			}
			else
			{
				goto create_account;
			}
		}
		else if (input == "3")
		{
			xiloader::console::output("Please enter your username.");
			std::cout << "\nPlease enter your username: ";
			std::cin >> g_Username;

			sendBuffer[0x82] = LOGIN_RECOVER;
			memcpy(sendBuffer + 0x00, g_Username.c_str(), 16);

			send(sock->s, sendBuffer, 131, 0);
			recv(sock->s, recvBuffer, 32, 0);

			switch (recvBuffer[0])
			{
			case SUCCESS_USERFOUND: 

				g_SecurityQuestionIDRecieved = *(UINT32*)(recvBuffer + 0x10);

				if (g_SecurityQuestionIDRecieved == 0)
				{
					xiloader::console::output(xiloader::color::error, "** A security question was not setup.");
					xiloader::console::output(xiloader::color::error, "** Please contact an admin.");
					closesocket(sock->s);
					sock->s = INVALID_SOCKET;
					return false;
				}

				closesocket(sock->s);
				sock->s = INVALID_SOCKET;
			    if (!xiloader::network::CreateConnection(sock, "54231"))
					return false;

				xiloader::console::output("Please answer the security question to reset your password.");

				if (g_SecurityQuestionIDRecieved == 1)
				{
					std::cout << "Question: What is your pets name?";
				}
				else if (g_SecurityQuestionIDRecieved == 2)
				{
					std::cout << "Question: In what year was your father born?";
				}
				else if (g_SecurityQuestionIDRecieved == 3)
				{
					std::cout << "Question: In what town or city was your first full time job?";
				}
				else if (g_SecurityQuestionIDRecieved == 4)
				{
					std::cout << "Question: What are the last five digits of your drivers licence number?";
				}
				else if (g_SecurityQuestionIDRecieved == 5)
				{
					std::cout << "Question: What is your spouse or partners mothers maiden name?";
				}

				std::cout << "\nYour Answer: ";
				std::getline(std::cin >> std::ws, g_SecurityQuestionAnswer);


				sendBuffer[0x82] = LOGIN_SQATTEMPT;
				memcpy(sendBuffer + 0x00, g_Username.c_str(), 16);
				memcpy(sendBuffer + 0x40, g_SecurityQuestionAnswer.c_str(), 64);
			    memcpy(sendBuffer + 0x80, std::to_string(g_SecurityQuestionIDRecieved).c_str(), 2);

				
				send(sock->s, sendBuffer, 131, 0);
				recv(sock->s, recvBuffer, 32, 0);

				switch (recvBuffer[0])
				{
				case SUCCESS_SQCHANGED:

					closesocket(sock->s);
					sock->s = INVALID_SOCKET;
					if (!xiloader::network::CreateConnection(sock, "54231"))
						return false;

					xiloader::console::output(xiloader::color::green, "Verified! Enter your new password below.");
				sq_password_change:

					std::cout << "\nNew Password (6-15 characters): ";
					std::cin >> g_NewPassword;
					std::cout << "Repeat New Password           : ";
					std::cin >> input;

					if (input != g_NewPassword)
					{
						xiloader::console::output(xiloader::color::error, "Passwords did not match! Please try again.");
						goto sq_password_change;
					}

					sendBuffer[0x82] = LOGIN_PASS;
					memcpy(sendBuffer + 0x00, g_Username.c_str(), 16);
					memcpy(sendBuffer + 0x10, g_Password.c_str(), 16);
					memcpy(sendBuffer + 0x20, g_NewPassword.c_str(), 16); // We use the email field (as 16)

					send(sock->s, sendBuffer, 131, 0);
					recv(sock->s, recvBuffer, 32, 0);

					switch (recvBuffer[0])
					{
					case SUCCESS_PASS:
						xiloader::console::output(xiloader::color::green, "Password updated!");
						closesocket(sock->s);
						sock->s = INVALID_SOCKET;
						return false;

					case ERROR_PASS:
						xiloader::console::output(xiloader::color::error, "Failed to change password..");
						closesocket(sock->s);
						sock->s = INVALID_SOCKET;
						return false;
					}

					break;
				case ERROR_SQFAILED:
					xiloader::console::output(xiloader::color::error, "Incorrect answer..  Try again.");
					closesocket(sock->s);
					sock->s = INVALID_SOCKET;
					return false;
				}
				break;
			case ERROR_USERFOUND:
				xiloader::console::output(xiloader::color::error, "No user with that name found.");
				closesocket(sock->s);
				sock->s = INVALID_SOCKET;
				return false;
			}

			xiloader::console::output(xiloader::color::error, "Error Unknown..");
			closesocket(sock->s);
			sock->s = INVALID_SOCKET;
			return false;
		}

	send_data:

		/* Send info to server and obtain response.. */
		send(sock->s, sendBuffer, 131, 0);
		recv(sock->s, recvBuffer, 32, 0);

		/* Handle the obtained result.. */
		switch (recvBuffer[0])
		{
		case SUCCESS_LOGIN: // Success (Login)
			xiloader::console::output(xiloader::color::success, "Successfully logged in as %s!", g_Username.c_str());
			sock->AccountId = *(UINT32*)(recvBuffer + 0x10);
			break;

		case SUCCESS_CREATE: // Success (Create Account)
			xiloader::console::output(xiloader::color::success, "Account successfully created!");
			sock->AccountId = *(UINT32*)(recvBuffer + 0x10);
			break;

		case ERROR_LOGIN: // Error (Login)
			xiloader::console::output(xiloader::color::error, "Failed to login. Invalid username or password.");
			closesocket(sock->s);
			sock->s = INVALID_SOCKET;
			return false;

		case ERROR_CREATE: // Error (Create Account)
			xiloader::console::output(xiloader::color::error, "Failed to create the new account. Username already taken.");
			closesocket(sock->s);
			sock->s = INVALID_SOCKET;
			return false;
		}


	main_menu:

		closesocket(sock->s);
		sock->s = INVALID_SOCKET;
		if (!xiloader::network::CreateConnection(sock, "54231"))
			return false;

		xiloader::console::output(" ");
		xiloader::console::output("==========================================================");
		xiloader::console::output("================      MAIN MENU    =======================");
		xiloader::console::output("==========================================================");
		xiloader::console::output("   1.) Play FFXI - Dark Aerith");
		xiloader::console::output("   2.) Change Email");
		xiloader::console::output("   3.) Change Password");
		xiloader::console::output("   4.) Setup Security Question");
		xiloader::console::output("   5.) Logout");
		xiloader::console::output("==========================================================");
		printf("\nEnter a selection: ");

		std::cin >> input;
		std::cout << std::endl;

		// Convert to int
		stringstream q1_id_con(input);
		q_id_i = 0;
		q1_id_con >> q_id_i;

		if (q_id_i < 1 || q_id_i > 5)
		{
			xiloader::console::output("Invalid selection..");
			goto main_menu;
		}

		if (input == "1")
		{
			sendBuffer[0x82] = SHUTDOWN;
			send(sock->s, sendBuffer, 131, 0);

			closesocket(sock->s);
			sock->s = INVALID_SOCKET;
			return true;
		}
		else if (input == "2")
		{
			xiloader::console::output("Verify your password then tell us what your new email should be?");

			PromptForConfirmPassword();

			if (g_ConfirmPassword != g_Password)
			{
				std::cout << std::endl;
				xiloader::console::output(xiloader::color::error, "Failed to verify password..");
				goto main_menu;
			}
			else
			{ 
				std::cout << "\nNew Email: ";
				std::cin >> g_Email;
				std::cout << std::endl;

				sendBuffer[0x82] = LOGIN_EMAIL;
				memcpy(sendBuffer + 0x00, g_Username.c_str(), 16);
				memcpy(sendBuffer + 0x10, g_Password.c_str(), 16);
				memcpy(sendBuffer + 0x20, g_Email.c_str(), 32);
			}
		}
		else if (input == "3")
		{
			xiloader::console::output("Verify your password then tell us what your new password should be?");

			PromptForConfirmPassword();

			if (g_ConfirmPassword != g_Password)
			{
				std::cout << std::endl;
				xiloader::console::output(xiloader::color::error, "Failed to verify password..");
				goto main_menu;
			}
			else
			{
				password_change:

				std::cout << "\nNew Password (6-15 characters): ";
				std::cin >> g_NewPassword;
				std::cout << "Repeat New Password           : ";
				std::cin >> input;

				if (input != g_NewPassword)
				{
					xiloader::console::output(xiloader::color::error, "Passwords did not match! Please try again.");
					goto password_change;
				}

				sendBuffer[0x82] = LOGIN_PASS;
				memcpy(sendBuffer + 0x00, g_Username.c_str(), 16);
				memcpy(sendBuffer + 0x10, g_Password.c_str(), 16);
				memcpy(sendBuffer + 0x20, g_NewPassword.c_str(), 16); // We use the email field (as 16)
			}
		}
		else if (input == "4")
		{
			xiloader::console::output("Verify your password first.");

			PromptForConfirmPassword();

			if (g_ConfirmPassword != g_Password)
			{
				std::cout << std::endl;
				xiloader::console::output(xiloader::color::error, "Failed to verify password..");
				goto main_menu;
			}
			else
			{
			    choose_ques:

				std::cout << std::endl;

				xiloader::console::output("What do you want your security question to be?");
				xiloader::console::output("   1.) What is your pets name?");
				xiloader::console::output("   2.) In what year was your father born?");
				xiloader::console::output("   3.) In what town or city was your first full time job?");
				xiloader::console::output("   4.) What are the last five digits of your drivers licence number?");
				xiloader::console::output("   5.) What is your spouse or partners mothers maiden name?");
				printf("\nEnter a selection: ");

				std::cin >> g_SecurityQuestionID;
				std::cout << std::endl;

				// Convert to int
				stringstream sq_id_con(g_SecurityQuestionID);
				int sq_id_i = 0;
				sq_id_con >> sq_id_i;

				if (sq_id_i < 1 || sq_id_i > 5)
				{
					xiloader::console::output("Invalid selection..");
					goto choose_ques;
				}

				std::cout << "\nYour Answer: ";
				std::getline(std::cin >> std::ws, g_SecurityQuestionAnswer);

				sendBuffer[0x82] = LOGIN_SEC_CODE;
				memcpy(sendBuffer + 0x00, g_Username.c_str(), 16);
				memcpy(sendBuffer + 0x10, g_Password.c_str(), 16);
				memcpy(sendBuffer + 0x40, g_SecurityQuestionAnswer.c_str(), 64);
				memcpy(sendBuffer + 0x80, g_SecurityQuestionID.c_str(), 2);
			}
		}
		else if (input == "5")
		{
			xiloader::console::output(xiloader::color::success, "Logged out successfully!\n");
			closesocket(sock->s);
			sock->s = INVALID_SOCKET;
			return false;
		}

		/* Send info to server and obtain response.. */
		send(sock->s, sendBuffer, 131, 0);
		recv(sock->s, recvBuffer, 32, 0);

		/* Handle the obtained result.. */
		switch (recvBuffer[0])
		{
		case SUCCESS_EMAIL: 
			xiloader::console::output(xiloader::color::success, "Successfully changed email!");
			goto main_menu;
			break;

		case SUCCESS_PASS: 
			xiloader::console::output(xiloader::color::success, "Successfully changed password!");
			closesocket(sock->s);
			sock->s = INVALID_SOCKET;
			return false;

		case SUCCESS_SEC_CODE: 
			xiloader::console::output(xiloader::color::success, "Successfully changed security question!");
			goto main_menu;
			break;

		case ERROR_EMAIL:
			xiloader::console::output(xiloader::color::error, "Failed to change email..");
			goto main_menu;
			break;

		case ERROR_PASS: 
			xiloader::console::output(xiloader::color::error, "Failed to change password..");
			goto main_menu;
			break;

		case ERROR_SEC_CODE:
			xiloader::console::output(xiloader::color::error, "Failed to change security question..");
			goto main_menu;
			break;
		}


		xiloader::console::output(xiloader::color::success, "Logged out!\n");
		closesocket(sock->s);
		sock->s = INVALID_SOCKET;
		return false;
	}

	/**
	* @brief Gets user's password
	*
	* @param null
	*
	* @return null
	*/
	void network::PromptForPassword()
	{
		std::cout << "Password: ";
		g_Password.clear();

		/* Read in each char and instead of displaying it. display a "*" */
		char ch;
		while ((ch = static_cast<char>(_getch())) != '\r')
		{
			if (ch == '\0')
				continue;
			else if (ch == '\b')
			{
				if (g_Password.size())
				{
					g_Password.pop_back();
					std::cout << "\b \b";
				}
			}
			else
			{
				g_Password.push_back(ch);
				std::cout << '*';
			}
		}
	}

	/**
	* @brief Gets user's password
	*
	* @param null
	*
	* @return null
	*/
	void network::PromptForConfirmPassword()
	{
		std::cout << "Verify Your Password: ";
		g_ConfirmPassword.clear();

		/* Read in each char and instead of displaying it. display a "*" */
		char ch;
		while ((ch = static_cast<char>(_getch())) != '\r')
		{
			if (ch == '\0')
				continue;
			else if (ch == '\b')
			{
				if (g_ConfirmPassword.size())
				{
					g_ConfirmPassword.pop_back();
					std::cout << "\b \b";
				}
			}
			else
			{
				g_ConfirmPassword.push_back(ch);
				std::cout << '*';
			}
		}
	}


	/**
	* @brief Change security question prompt
	*
	* @param null
	*
	* @return null
	*/
	void network::ChangeSecurityQuestion()
	{
	choose_ques:
		std::cout << "\n";
		xiloader::console::output("==========================================================");
		xiloader::console::output("Question Choice");
		xiloader::console::output("   1.) What is your pets name?");
		xiloader::console::output("   2.) In what year was your father born?");
		xiloader::console::output("   3.) In what town or city was your first full time job?");
		xiloader::console::output("   4.) What are the last five digits of your drivers licence number?");
		xiloader::console::output("   5.) What is your spouse or partners mothers maiden name?");
		xiloader::console::output("==========================================================");
		printf("\nEnter a selection: ");

		std::cin >> g_SecurityQuestionID;
		std::cout << std::endl;

		// Convert to int
		stringstream sq_id_con(g_SecurityQuestionID);
		UINT32 sq_id_i = 0;
		sq_id_con >> sq_id_i;

		if (sq_id_i < 1 || sq_id_i > 5)
		{
			xiloader::console::output("Invalid selection..");
			goto choose_ques;
		}

		std::cout << "\nYour Answer: ";
		std::getline(std::cin >> std::ws, g_SecurityQuestionAnswer);
	
		std::cout << std::endl;
	}

    /**
     * @brief Data communication between the local client and the game server.
     *
     * @param lpParam   Thread param object.
     *
     * @return Non-important return.
     */
    DWORD __stdcall network::FFXiDataComm(LPVOID lpParam)
    {
        auto sock = (xiloader::datasocket*)lpParam;

        int sendSize = 0;
        char recvBuffer[4096] = { 0 };
        char sendBuffer[4096] = { 0 };

        while (g_IsRunning)
        {
            /* Attempt to receive the incoming data.. */
            struct sockaddr_in client;
            unsigned int socksize = sizeof(client);
            if (recvfrom(sock->s, recvBuffer, sizeof(recvBuffer), 0, (struct sockaddr*)&client, (int*)&socksize) <= 0)
                continue;

            switch (recvBuffer[0])
            {
            case 0x0001:
                sendBuffer[0] = 0xA1u;
                memcpy(sendBuffer + 0x01, &sock->AccountId, 4);
                memcpy(sendBuffer + 0x05, &sock->ServerAddress, 4);
                xiloader::console::output(xiloader::color::warning, "Sending account id..");
                sendSize = 9;
                break;

            case 0x0002:
            case 0x0015:
                memcpy(sendBuffer, (char*)"\xA2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x58\xE0\x5D\xAD\x00\x00\x00\x00", 25);
                xiloader::console::output(xiloader::color::warning, "Sending key..");
                sendSize = 25;
                break;

            case 0x0003:
                xiloader::console::output(xiloader::color::warning, "Receiving character list..");
                for (auto x = 0; x <= recvBuffer[1]; x++)
                {
                    g_CharacterList[0x00 + (x * 0x68)] = 1;
                    g_CharacterList[0x02 + (x * 0x68)] = 1;
                    g_CharacterList[0x10 + (x * 0x68)] = (char)x;
                    g_CharacterList[0x11 + (x * 0x68)] = 0x80u;
                    g_CharacterList[0x18 + (x * 0x68)] = 0x20;
                    g_CharacterList[0x28 + (x * 0x68)] = 0x20;

                    memcpy(g_CharacterList + 0x04 + (x * 0x68), recvBuffer + 0x14 * (x + 1), 4); // Character Id
                    memcpy(g_CharacterList + 0x08 + (x * 0x68), recvBuffer + 0x10 * (x + 1), 4); // Content Id
                }
                sendSize = 0;
                break;
            }

            if (sendSize == 0)
                continue;

            /* Send the response buffer to the server.. */
            auto result = sendto(sock->s, sendBuffer, sendSize, 0, (struct sockaddr*)&client, socksize);
            if (sendSize == 72 || result == SOCKET_ERROR || sendSize == -1)
            {
                shutdown(sock->s, SD_SEND);
                closesocket(sock->s);
                sock->s = INVALID_SOCKET;

                xiloader::console::output("Server connection done; disconnecting!");
                return 0;
            }

            sendSize = 0;
            Sleep(100);
        }

        return 0;
    }

    /**
     * @brief Data communication between the local client and the lobby server.
     *
     * @param lpParam   Thread param object.
     *
     * @return Non-important return.
     */
    DWORD __stdcall network::PolDataComm(LPVOID lpParam)
    {
        SOCKET client = *(SOCKET*)lpParam;
        unsigned char recvBuffer[1024] = { 0 };
        int result = 0, x = 0;
        time_t t = 0;
        bool bIsNewChar = false;

        do
        {
            /* Attempt to receive incoming data.. */
            result = recv(client, (char*)recvBuffer, sizeof(recvBuffer), 0);
            if (result <= 0)
            {
                xiloader::console::output(xiloader::color::error, "Client recv failed: %d", WSAGetLastError());
                break;
            }

            char temp = recvBuffer[0x04];
            memset(recvBuffer, 0x00, 32);

            switch (x)
            {
            case 0:
                recvBuffer[0] = 0x81;
                t = time(NULL);
                memcpy(recvBuffer + 0x14, &t, 4);
                result = 24;
                break;

            case 1:
                if (temp != 0x28)
                    bIsNewChar = true;
                recvBuffer[0x00] = 0x28;
                recvBuffer[0x04] = 0x20;
                recvBuffer[0x08] = 0x01;
                recvBuffer[0x0B] = 0x7F;
                result = bIsNewChar ? 144 : 24;
                if (bIsNewChar) bIsNewChar = false;
                break;
            }

            /* Echo back the buffer to the server.. */
            if (send(client, (char*)recvBuffer, result, 0) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Client send failed: %d", WSAGetLastError());
                break;
            }

            /* Increase the current packet count.. */
            x++;
            if (x == 3)
                break;

        } while (result > 0);

        /* Shutdown the client socket.. */
        if (shutdown(client, SD_SEND) == SOCKET_ERROR)
            xiloader::console::output(xiloader::color::error, "Client shutdown failed: %d", WSAGetLastError());
        closesocket(client);

        return 0;
    }

    /**
     * @brief Starts the data communication between the client and server.
     *
     * @param lpParam   Thread param object.
     *
     * @return Non-important return.
     */
    DWORD __stdcall network::FFXiServer(LPVOID lpParam)
    {
        /* Attempt to create connection to the server.. */
        if (!xiloader::network::CreateConnection((xiloader::datasocket*)lpParam, "54230"))
            return 1;

        /* Attempt to start data communication with the server.. */
        CreateThread(NULL, 0, xiloader::network::FFXiDataComm, lpParam, 0, NULL);
        Sleep(200);

        return 0;
    }

    /**
     * @brief Starts the local listen server to lobby server communications.
     *
     * @param lpParam   Thread param object.
     *
     * @return Non-important return.
     */
    DWORD __stdcall network::PolServer(LPVOID lpParam)
    {
        UNREFERENCED_PARAMETER(lpParam);

        SOCKET sock, client;

        /* Attempt to create listening server.. */
        if (!xiloader::network::CreateListenServer(&sock, IPPROTO_TCP, g_ServerPort.c_str()))
            return 1;

        while (g_IsRunning)
        {
            /* Attempt to accept incoming connections.. */
            if ((client = accept(sock, NULL, NULL)) == INVALID_SOCKET)
            {
                xiloader::console::output(xiloader::color::error, "Accept failed: %d", WSAGetLastError());

                closesocket(sock);
                return 1;
            }

            /* Start data communication for this client.. */
            CreateThread(NULL, 0, xiloader::network::PolDataComm, &client, 0, NULL);
        }

        closesocket(sock);
        return 0;
    }

}; // namespace xiloader
