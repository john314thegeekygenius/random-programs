/*
	transfer.cpp
	allows for remote transfer of a file from a ssh client to your computer
	10/3/2022
*/


#include <iostream>
#include <stdlib.h>
#include <string>
#include <vector>

#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <errno.h>
#include <string.h>
#include <fstream>

ssh_session my_ssh_session;

bool prgRunning = false;
std::string terminalPath = "";
std::vector<std::string> terminalInfo;
std::string terminalData;
std::ofstream terminalFile;
 
 ////////////////////////////////////////////////////////////////
 ////////////////////// START CODE FROM SSHLib.org
 
int verify_knownhost(ssh_session session)
{
    enum ssh_known_hosts_e state;
    unsigned char *hash = NULL;
    ssh_key srv_pubkey = NULL;
    size_t hlen;
    char buf[10];
    char *hexa;
    char *p;
    int cmp;
    int rc;
 
    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA1,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    state = ssh_session_is_known_server(session);
    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            /* OK */
 
            break;
        case SSH_KNOWN_HOSTS_CHANGED:
            fprintf(stderr, "Host key for server changed: it is now:\n");
            ssh_print_hexa("Public key hash", hash, hlen);
            fprintf(stderr, "For security reasons, connection will be stopped\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_OTHER:
            fprintf(stderr, "The host key for this server was not found but an other"
                    "type of key exists.\n");
            fprintf(stderr, "An attacker might change the default server key to"
                    "confuse your client into thinking the key does not exist\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            fprintf(stderr, "Could not find known host file.\n");
            fprintf(stderr, "If you accept the host key here, the file will be"
                    "automatically created.\n");
 
            /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */
 
        case SSH_KNOWN_HOSTS_UNKNOWN:
            hexa = ssh_get_hexa(hash, hlen);
            fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
            fprintf(stderr, "Public key hash: %s\n", hexa);
            ssh_string_free_char(hexa);
            ssh_clean_pubkey_hash(&hash);
            p = fgets(buf, sizeof(buf), stdin);
            if (p == NULL) {
                return -1;
            }
 
            cmp = strncasecmp(buf, "yes", 3);
            if (cmp != 0) {
                return -1;
            }
 
            rc = ssh_session_update_known_hosts(session);
            if (rc < 0) {
                fprintf(stderr, "Error %s\n", strerror(errno));
                return -1;
            }
 
            break;
        case SSH_KNOWN_HOSTS_ERROR:
            fprintf(stderr, "Error %s", ssh_get_error(session));
            ssh_clean_pubkey_hash(&hash);
            return -1;
    }
 
    ssh_clean_pubkey_hash(&hash);
    return 0;
}

int get_command_data(ssh_session session, std::string cmd)
{
	ssh_channel channel;
	int rc;

	channel = ssh_channel_new(session);
	if (channel == NULL) return SSH_ERROR;

	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK)
	{
	ssh_channel_free(channel);
	return rc;
	}

	rc = ssh_channel_request_exec(channel, cmd.c_str());
	if (rc != SSH_OK)
	{
	  ssh_channel_close(channel);
	  ssh_channel_free(channel);
	  return rc;
	}

	char buffer[2048] = {0};
	int nbytes;
	 
	nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	while (nbytes > 0){
		nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	}

	std::string tmp = "";
	terminalInfo.clear();
	for(int i = 0; i < 2048; i++){
		if(buffer[i] == 0){
			break;
		}
		if(buffer[i] == '\n' || buffer[i] == '\r'){
			terminalInfo.push_back(tmp);
			tmp = "";
		}else{
			tmp += (buffer[i]);
		}
	}
	 
	if (nbytes < 0)
	{
	  ssh_channel_close(channel);
	  ssh_channel_free(channel);
	  return SSH_ERROR;
	}

  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);
 
  return SSH_OK;
}

int scp_receive(ssh_session session, ssh_scp scp)
{
  int rc;
  int size, mode;
  char *filename, *buffer;
 
  rc = ssh_scp_pull_request(scp);
  if (rc != SSH_SCP_REQUEST_NEWFILE)
  {
    fprintf(stderr, "Error receiving information about file: %s\n",
            ssh_get_error(session));
    return SSH_ERROR;
  }
 
  size = ssh_scp_request_get_size(scp);
  filename = strdup(ssh_scp_request_get_filename(scp));
  mode = ssh_scp_request_get_permissions(scp);
  printf("Receiving file %s, size %d, permissions 0%o\n",
          filename, size, mode);
  free(filename);
 
  buffer = (char*)malloc(size);
  if (buffer == NULL)
  {
    fprintf(stderr, "Memory allocation error\n");
    return SSH_ERROR;
  }
 
  ssh_scp_accept_request(scp);
  rc = ssh_scp_read(scp, buffer, size);
  if (rc == SSH_ERROR)
  {
    fprintf(stderr, "Error receiving file data: %s\n",
            ssh_get_error(session));
    free(buffer);
    return rc;
  }
  printf("Done\n");
  
  terminalData = std::string(buffer);
 
  free(buffer);
 
  rc = ssh_scp_pull_request(scp);
  if (rc != SSH_SCP_REQUEST_EOF)
  {
    fprintf(stderr, "Unexpected request: %s\n",
            ssh_get_error(session));
    return SSH_ERROR;
  }
 
  return SSH_OK;
}

/////////////////////////////////////////////////////
// END SSH CODE
/////////////////

void cmdHelp(std::vector<std::string> args){
	std::cout << "Commands:\n" << 
			 "help\t- Print this text\n" <<
		     "ls\t- list files in current directory\n" <<
		     "cd <dir>\t- change the current directory\n" <<
		     "cp <fname>\t- copy a file over\n" <<
		     "head <fname>\t- print a few lines from a file\n" << 
			 "exit\t- exit the program\n" <<
		     std::endl;
};

void cmdListDir(std::vector<std::string> args){
	std::string tempdir = terminalPath;

	if(args.size() == 2){
		terminalPath = args[1];
	}
	
	get_command_data(my_ssh_session, ("ls -1 "+terminalPath));

	terminalPath = tempdir;

	for(std::string s : terminalInfo){
		if(s.at(s.length()-1)=='/'){
			std::cout << "DIR: " << s << std::endl;
			s.pop_back();
		}else if(s.at(s.length()-1)=='*'){
			std::cout << "EXE: " << s << std::endl;
			s.pop_back();
		}else{
			std::cout << "FILE: " << s << std::endl;
		}
	}
};

void cmdChangeDir(std::vector<std::string> args){
	// Make sure it's a valid directory
	if(args.size() != 2){
		std::cout << "Use: cd <dir>" << std::endl;
		return;
	}
	if(args[1].compare("..")==0){
		// Go back a dir
		std::string temp = "";
		int dirdepth = terminalPath.length();
		for(int i = terminalPath.length()-1; i >= 0; i--){
			if(terminalPath[i] == '.'){
				dirdepth = i+1;
				break;
			}
		}
		for(int i = 0; i < terminalPath.length()-dirdepth; i++){
			temp += terminalPath[i];
		}
		terminalPath = temp;
		return;
	}
	if(args[1].compare(".")==0){
		// Go back to home
		terminalPath = "";
		return ;
	}
	get_command_data(my_ssh_session, ("ls -1 "+terminalPath));

	if(args[1].at(args[1].length()-1) != '/'){
		// Add it
		args[1].push_back('/');
	}

	for(std::string s : terminalInfo){
		if(s.at(s.length()-1)=='/'){
			if(s.compare(args[1])==0){
				// Valid dir
				terminalPath += args[1];
				return;
			}
		}
	}
	std::cout << "Invalid directory " << args[1] << std::endl;
};

void cmdCopy(std::vector<std::string> args){
	ssh_scp scp;
	int rc;
	if(args.size() != 2){
		std::cout << "Use: cp <filename> " << std::endl;
		return;
	}
	
	scp = ssh_scp_new(my_ssh_session, SSH_SCP_READ, (terminalPath+args[1]).c_str());
	if (scp == NULL){
		fprintf(stderr, "Error allocating scp session: %s\n",
				ssh_get_error(my_ssh_session));
		return ;
	}

	rc = ssh_scp_init(scp);
	if (rc != SSH_OK)
	{
		fprintf(stderr, "Error initializing scp session: %s\n",
			ssh_get_error(my_ssh_session));
		ssh_scp_free(scp);
		return ;
	}

	// Get the file
	scp_receive(my_ssh_session,scp);

	// Save the file
	terminalFile.open(args[1]);
	if(terminalFile.is_open()){
	  terminalFile << terminalData;
	  terminalFile.close();
	  std::cout << "Saved file to " << args[1] << std::endl;
	}else{
	  std::cout << "Error saving file " << args[1] << std::endl;
	}

	ssh_scp_close(scp);
	ssh_scp_free(scp);
};

void cmdHeadPrint(std::vector<std::string> args){
	// Print the first few lines of a file
	if(args.size() == 2){
		get_command_data(my_ssh_session, ("head "+terminalPath+args[1]));
		for(std::string s : terminalInfo){
			std::cout << s << std::endl;
		}
	}else{
		std::cout << "Use: head <file>" << std::endl;
	}
};



void cmdExit(std::vector<std::string> args){
	prgRunning = false;
};

typedef struct {
	std::string tag;
	void (*run)(std::vector<std::string> args);
}commandPair;

std::vector<commandPair> commands = {
	{"help",&cmdHelp},
	{"ls",&cmdListDir},
	{"cd",&cmdChangeDir},
	{"cp",&cmdCopy},
	{"head",&cmdHeadPrint},
	{"exit",&cmdExit},
};

void doTerminal(){
	std::vector<std::string> args;
	
	std::cout << terminalPath << ":>" << std::flush;
	
	std::string input;
	std::getline(std::cin,input);

	std::string s = "";
	for(int i = 0; i < input.length(); i++){
		if(input.at(i)==' '){
			args.push_back(s);
			s = "";
		}else{
			s.push_back(input.at(i));
		}
	}
	if(s.length()){
		args.push_back(s);
	}

	if(args.size()){
		bool goodCommand = false;
		for(commandPair &p : commands){
			if(p.tag.compare(args[0])==0){
				// Run that command
				p.run(args);
				goodCommand = true;
				break;
			}
		}
		if(goodCommand == false){
			std::cout << args[0] << " is not a valid command!" << std::endl;
		}
	}
};

void getSSHTerminal(){
	char termline[1024];
};

int main(int argc, char *argv[]){

	std::string hostString = "localhost"; // Default host address
	std::string hostPass = ""; // Default host password
	
	std::string tempstr;
	std::cout << "Welcome to SSH Transfer" << std::endl;
	std::cout << "---------------------------------------------------" << std::endl;
	std::cout << "Please enter server to connect to:" << std::flush;

	std::getline(std::cin,tempstr);
	if(tempstr.length()){
		hostString = tempstr;
	}
	
	my_ssh_session = ssh_new();
	int rc = 0;

	if (my_ssh_session == NULL){
		std::cout << "SSH session failed!" << std::endl;
	}
	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, hostString.c_str());

	rc = ssh_connect(my_ssh_session);
	if (rc != SSH_OK){
		std::cout << "Error connecting to " << hostString << ": " << std::endl;
		std::cout << ssh_get_error(my_ssh_session) << std::endl;
		return 0;
	}

	// Verify the server's identity
	if (verify_knownhost(my_ssh_session) < 0){
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		return 0;
	}

	// Authenticate ourselves
	std::string password = "";
	password = getpass("Password: ");
	if(password.length()==0){
		password = hostPass;
	}
	rc = ssh_userauth_password(my_ssh_session, NULL, password.c_str());
	if (rc != SSH_AUTH_SUCCESS){
		std::cout << "Error authenticating with password:" << std::endl;
		std::cout << ssh_get_error(my_ssh_session) << std::endl;

		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);

		return 0;
	}
  
	std::cout << "---------------------------------------------------" << std::endl;
	cmdHelp({});

	prgRunning = true;

	while(prgRunning){
		doTerminal();
	}

	if(my_ssh_session!=NULL){
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
	}

	return 0;
};
