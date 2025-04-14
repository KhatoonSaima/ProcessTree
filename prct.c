/*
 * This program searches for processes in the process tree rooted at a given process (root_process)
 * and provides various details based on the selected option. It supports listing descendants, 
 * defunct processes, immediate/non-immediate children, siblings, and grandchildren etc. 
 * It can also send signals (SIGKILL, SIGSTOP, SIGCONT) to descendants and manage zombie processes.
 * The program parses the /proc directory (Linux only) to extract process relationships dynamically.
 */
 /*
 Usage: ./prct [root_process] [process_id] [Option: dc|ds|id|lg|lz|df|op|gc|do|so|pz|sk|st|dt|rp]
-dc: Lists the number of all descendents of process_id that are defunct
-ds: Lists the PIDs of all the non-direct descendants of process_id
-id: Lists the PIDs of all the immediate descendants of process_id
-lg: Lists the PIDs of all the sibling processes of process_id
-lz: Lists the PIDs of all the sibling processes of process_id that are defunct
-df: Lists the PIDs of all descendents of process_id that are defunct
-gc: Lists the PIDs of all the grandchildren of process_id
-do: Prints the status of the process_id (Defunct/ Not Defunct)
-pz: Kills the parents of all zombie process that are the descendants of proceed_id
-sk: All descendants of process_id are killed using SIGKILL
-st: All descendants of process_id are stopped using SIGSTOP
-dt: All descendants of process_id currently stopped are continued using SIGCONT
-rp: root_process is killed using SIGKILL

Author: Saima Khatoon
Date: 28-02-2025
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>

#define MAX_PROCESSES 1024
#define MAX_PATH 1024

// To store count of zombie processes
int zombiecount = 0;
// To store count of sibling processes
int sibling_count = 0;

// Function prototypes
uid_t get_process_uid(pid_t pid);
int find_user_bash_pids(pid_t *bash_pids, int max_pids);
int belongs_to_bash_tree(pid_t root_process, pid_t process_id);
int get_parent_processid(pid_t target);
int is_descendant(int root_process, int process_id);
int count_zombie_process(int process_id);
int is_zombie(int process_id);
void get_direct_children(pid_t parent, pid_t *children, int *count);
int is_number(const char *str);
void list_siblings(pid_t process_id, int check_defunct);
void list_zombie_descendants(int process_id);
void find_descendants(pid_t root_pid, pid_t *descendants, int *count);
void list_grandchildren(pid_t process_id);
void get_children_pids(pid_t parent_pid, int level , int *found_grandchildren);
void check_defunct(pid_t process_id);
int check_orphan(pid_t process_id);
void kill_zombie_parents(pid_t process_id);
void send_signal_to_descendants(pid_t root_pid, int signal);
void kill_root_process(pid_t root_pid);

// Get the UID of a process from /proc/[PID]/status
uid_t get_process_uid(pid_t pid) {
    char path[64], buffer[1024];
    int fd, bytes_read;
    
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    fd = open(path, O_RDONLY);
    if (fd == -1) return -1;

    bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (bytes_read <= 0) return -1;

    buffer[bytes_read] = '\0';

    char *uid_line = strstr(buffer, "Uid:");
    if (uid_line) {
        uid_t uid;
        sscanf(uid_line + 5, "%d", &uid);
        return uid;
    }

    return -1;
}

// Find all Bash process PIDs owned by the user
int find_user_bash_pids(pid_t *bash_pids, int max_pids) 
{
    DIR *dir;
    struct dirent *entry;
    int count = 0;
    uid_t user_uid = getuid();  // Get the real UID of the current user

    dir = opendir("/proc");
    if (!dir) 
    {
        perror("opendir failed");
        return -1;
    }

    while ((entry = readdir(dir))) 
    {
        pid_t pid = atoi(entry->d_name);
        if (pid > 0 && count < max_pids) 
        {
            if (get_process_uid(pid) != user_uid) continue;  // Check if process belongs to user

            char path[64], buffer[1024];
            snprintf(path, sizeof(path), "/proc/%d/status", pid);
            int fd = open(path, O_RDONLY);
            if (fd == -1) continue;

            int bytes_read = read(fd, buffer, sizeof(buffer) - 1);
            close(fd);
            if (bytes_read <= 0) continue;

            buffer[bytes_read] = '\0';

            if (strstr(buffer, "Name:\tbash")) 
            {  // Check if process is Bash
                bash_pids[count++] = pid;
            }
        }
    }

    closedir(dir);
    return count;
}

// Check if both root_process and process_id belong to a user-owned Bash tree
int belongs_to_bash_tree(pid_t root_process, pid_t process_id) {
    pid_t bash_pids[100];  // Store up to 100 Bash PIDs
    int bash_count = find_user_bash_pids(bash_pids, 100);

    if (bash_count == 0) return 0;  // No Bash processes found

    for (int i = 0; i < bash_count; i++) {
        if (is_descendant(bash_pids[i], root_process) && is_descendant(bash_pids[i], process_id)) {
            return 1;  // Both belong to the same Bash tree
        }
    }
    return 0;
}

// Check if process belong to the root process or not
// Function to check if a process is a descendant of the root process
int is_descendant(int root_process, int process_id)
{
   int ppid = process_id;

   // Traverse up the process tree until reaching root_process or PID 1
   while (ppid != 1 && ppid != root_process) {
        ppid = get_parent_processid(ppid);
        if (ppid == -1) 
            return 0; // Error case
    }

    return (ppid == root_process);
}

// Function to get the PPID of a process from /proc/[PID]/status
int get_parent_processid(pid_t target) 
{
    int ppid = -1;
    char line[MAX_PATH], path[MAX_PATH];
    snprintf(path, sizeof(path), "/proc/%d/status", target);
    FILE *fp = fopen(path, "r");

    if (!fp) 
    {
        // For debugging purpose
        //printf("Error opening process status file %d \n", target);
        return -1;
    }

    // Read the file line by line to find PPid
    // This will give the parent id
    while (fgets(line, sizeof(line), fp)) 
    {
        if (strncmp(line, "PPid:", 5) == 0)  // checking the matching string "Ppid:" in each line
        {
            sscanf(line + 6, "%d", &ppid);
            break;
        }
    }
    //printf("Parent process id is: %d\n", ppid);
    fclose(fp);
    return ppid;
}

// Option1: -dc
// Function to count the number of zombie processes
int count_zombie_process(int process_id)
{
    DIR *dir;
    struct dirent *entry;
    int count = 0;
    uid_t user_uid = getuid();  // Get the real UID of the current user

    // Open /proc directory
    dir = opendir("/proc");
    if (!dir) 
    {
        perror("opendir failed");
        return -1;
    }

    // Iterate over all directories in /proc
    while ((entry = readdir(dir))) 
    {
        pid_t pid = atoi(entry->d_name);
        if (pid > 0) 
        {  
            // Ignore non-numeric entries
            pid_t ppid = get_parent_processid(pid);
            
            // Check if this process is a descendant
            while (ppid > 1)
            {
                if (ppid == process_id) 
                {
                    if (is_zombie(pid)) 
                    {
                        zombiecount++;
                    }
                    break;
                }
                ppid = get_parent_processid(ppid);
            }
        }
    }

    closedir(dir);
    return zombiecount;
}

// Function to check if a process is a zombie
int is_zombie(int process_id)
{
    char line[MAX_PATH], path[MAX_PATH];
    snprintf(path, sizeof(path), "/proc/%d/status", process_id);
    FILE *fp = fopen(path, "r");
    if (!fp) 
    {
        // For debugging purpose
        //printf("Error opening process status file%d\n", process_id );
        return -1;
    }

    // Read the file line by line to find PPid
    // This will give the parent id
    while (fgets(line, sizeof(line), fp)) 
    {
        if (strncmp(line, "State:	Z (zombie)", 17) == 0)  // checking the matching string "State: Z (zombie)" in each line
        {
            sscanf(line + 17, "%d", &process_id);
            //printf ("Zombie process is: %d\n", process_id);
            return 1;
        }
    }
    fclose(fp);

    return 0;
}

// Option2: -ds
// Function to find all descendants of a process
void find_descendants(pid_t root_pid, pid_t *descendants, int *count) 
{
    struct dirent *entry;
    DIR *dir = opendir("/proc");

    if (!dir) 
    {
        perror("opendir failed");
        return;
    }

    *count = 0;
    while ((entry = readdir(dir)) != NULL) 
    {
        if (!is_number(entry->d_name)) continue;  // Skip non-numeric directories

        pid_t pid = atoi(entry->d_name);
        pid_t ppid = get_parent_processid(pid);

        // If this process is a descendant of root_pid
        while (ppid > 1) 
        {
            if (ppid == root_pid) 
            {
                descendants[(*count)++] = pid;
                break;
            }
            ppid = get_parent_processid(ppid);  // Move up the hierarchy
        }
    }

    closedir(dir);
}

// Option3: -id
// Function to get immediate children of a process
void get_direct_children(pid_t parent, pid_t *children, int *count) 
{
    *count = 0;
    struct dirent *entry;
    DIR *dir = opendir("/proc");

    if (!dir) 
    {
        perror("opendir failed");
        return;
    }

    while ((entry = readdir(dir)) != NULL) 
    {
        if (!is_number(entry->d_name)) continue;  // Skip non-numeric entries

        pid_t pid = atoi(entry->d_name);
        if (get_parent_processid(pid) == parent) 
        {
            children[(*count)++] = pid;
        }
    }
    closedir(dir);
}

// Function to check if a string contains only digits (valid PID)
int is_number(const char *str) 
{
    while (*str) 
    {
        if (!isdigit(*str)) return 0;
        str++;
    }
    return 1;
}

// Option4 & 5: -lg and -lz
// Function to list all siblings of a process
void list_siblings(pid_t process_id, int check_defunct) 
{
    pid_t parent_pid = get_parent_processid(process_id);
    char path[64];
    FILE *file;
    pid_t sibling_pid;

    if (parent_pid == -1) 
    {
        printf("Process %d does not exist or parent not found.\n", process_id);
        return;
    }

    snprintf(path, sizeof(path), "/proc/%d/task/%d/children", parent_pid, parent_pid);
    file = fopen(path, "r");
    if (!file) 
    {
        printf("No siblings found for process %d\n", process_id);
        return;
    }

    //printf("Siblings of Process %d%s:\n", process_id, check_defunct ? " (Defunct only)" : "");

    while (fscanf(file, "%d", &sibling_pid) == 1) 
    {
        if (sibling_pid != process_id) 
        {
            if (check_defunct) 
            {
                if (is_zombie(sibling_pid)) 
                {
                    printf("%d\n", sibling_pid);
                    sibling_count++;
                }
            } 
            else 
            {
                printf("%d\n", sibling_pid);
                sibling_count++;
            }
        }
    }

    fclose(file);
}

// Option6: -df
// Function to print all the zombie descendants 
void list_zombie_descendants(int process_id)
{
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    // Open /proc directory
    dir = opendir("/proc");
    if (!dir) 
    {
        perror("opendir failed");
        //return -1;
    }

    // Iterate over all directories in /proc
    while ((entry = readdir(dir))) 
    {
        pid_t pid = atoi(entry->d_name);
        if (pid > 0) 
        { 
            // Ignore non-numeric entries
            pid_t ppid = get_parent_processid(pid);
            
            // Check if this process is a descendant
            while (ppid > 1)
            {
                if (ppid == process_id) 
                {
                    if (is_zombie(pid)) 
                    {
                        //Listing zombie process
                        printf("%d\n", pid);
                    }
                    break;
                }
                ppid = get_parent_processid(ppid);
            }
        }
    }

    closedir(dir);
}

// Option7: -gc
// Function to list all grandchildren of process_id
void list_grandchildren(pid_t process_id) 
{
    //printf("Grandchildren of Process %d:\n", process_id);
    int found_grandchildren = 0;  // Flag to track if we find any grandchildren
    get_children_pids(process_id, 1, &found_grandchildren);  // Start at level 1 (children)
    
    if (!found_grandchildren) 
    {
        printf("No grandchildren.\n");
    }
}

// Function to get children PIDs from /proc/[PID]/task/[TID]/children
void get_children_pids(pid_t parent_pid, int level , int *found_grandchildren) 
{
    char path[MAX_PATH];
    FILE *file;
    int child_pid;

    // Open the children file for the parent process
    snprintf(path, sizeof(path), "/proc/%d/task/%d/children", parent_pid, parent_pid);
    file = fopen(path, "r");
    if (!file) 
    {
        return;  // No children or process doesn't exist
    }

    int children_found = 0;  // Flag to track if any child is found at this level

    // Read child PIDs from the file
    while (fscanf(file, "%d", &child_pid) == 1) 
    {
        if (level == 2) 
        {  
            // If level == 2, print the child as a grandchild
            printf("%d\n", child_pid);
            *found_grandchildren = 1;  // Mark that we found a grandchild
        }

        // Recursively call for the children to get their children (grandchildren)
        get_children_pids(child_pid, level + 1, found_grandchildren);

        children_found = 1;  // Mark that we've found at least one child
    }

    fclose(file);

    // If no grandchildren are found at level 2, print no grandchildren message
    if (!children_found && level == 1) 
    {
        // No children found for this process, so we skip
    }
}

// Option8: -do
// Function to check if a process is defunct
void check_defunct(pid_t process_id) 
{
    if (is_zombie(process_id) == 1) 
    {
        printf("Process %d is Defunct (Zombie)\n", process_id);
    } 
    else if (is_zombie(process_id) == 0) 
    {
        printf("Process %d is Not Defunct\n", process_id);
    } 
}

// Function to check if a process is orphaned
int check_orphan(pid_t process_id) 
{
    pid_t ppid = get_parent_processid(process_id);

    if (ppid == 1) 
        return 1;
    else if (ppid > 1) 
        return 0;
    else
        return 0;
}

// Option9: -pz
// -pz: Kills the parents of all zombie process that are the descendants of process_id
void kill_zombie_parents(pid_t process_id) 
{
    DIR *dir;
    struct dirent *entry;
    char path[MAX_PATH];
    FILE *status_file;
    char line[MAX_PATH];
    pid_t pid, ppid;
    char state;

    // Open the /proc directory
    dir = opendir("/proc");
    if (dir == NULL) 
    {
        perror("opendir");
        exit(EXIT_FAILURE);
    }

    // Iterate through all entries in /proc
    while ((entry = readdir(dir)) != NULL) 
    {
        // Check if the entry is a directory and represents a process ID
        if (entry->d_type == DT_DIR && atoi(entry->d_name) != 0) {
            pid = atoi(entry->d_name);

            // Skip the process_id itself
            if (pid == process_id)
            {
                continue;
            }

            // Construct the path to the process's status file
            snprintf(path, sizeof(path), "%s/%d/status", "/proc", pid);

            // Open the status file
            status_file = fopen(path, "r");
            if (status_file == NULL) 
            {
                // Process may have terminated, skip it
                continue;
            }

            // Read the status file to find PPid and State
            ppid = -1;
            state = '\0';
            while (fgets(line, sizeof(line), status_file)) 
            {
                if (strncmp(line, "PPid:", 5) == 0) 
                {
                    sscanf(line, "PPid:\t%d", &ppid);
                } 
                else if (strncmp(line, "State:", 6) == 0) 
                {
                    sscanf(line, "State:\t%c", &state);
                }
            }

            fclose(status_file);

            // Check if the process is a zombie and a descendant of process_id
            if (state == 'Z' && is_descendant(process_id, pid)) 
            {
                // Kill the parent of the zombie process
                printf("Killing parent of zombie process %d (PPid: %d)\n", pid, ppid);
                if (kill(ppid, SIGKILL) == -1) 
                {
                    perror("kill");
                }
            }
        }
    }
  
    closedir(dir);
}


// Option 10, 11, 12: -sk, -st, -dt
// It sends SIGKILL, SIGSTOP and SIGCONT signals to the process
// Function to send signal to collected descendants (killing bottom-up)
void send_signal_to_descendants(pid_t root_pid, int signal) 
{
    // Get all descendants of process_id
    pid_t descendants[MAX_PROCESSES];   // Array to store descendant PIDs
    int descendant_count = 0;
    find_descendants(root_pid, descendants, &descendant_count);

    // Now send signals in reverse order (bottom-up)
    for (int i = descendant_count - 1; i >= 0; i--) 
    {
        if (kill(descendants[i], signal) == 0) 
        {
            printf("Signal %d sent to process %d\n", signal, descendants[i]);
        } 
        else 
        {
            perror("Failed to send signal");
        }
    }
}

// Option13: -rp
// -rp: root_process is killed using KILL
void kill_root_process(pid_t root_pid) 
{
    //printf("getpid:%d\n", getpid());
    // Kill all its childrens first, then only kill root process
    // send_signal_to_descendants(root_pid, SIGKILL);

    // Killing directly the root process, without killing its child processes
    if (kill(root_pid, SIGKILL) == 0) 
    {
        printf("Root process (PID %d) killed successfully.\n", root_pid);
    } 
    else 
    {
        perror("Failed to kill the root process");
    }
}

int main(int argc, char **argv)
{
    // Number of arguments can not be less than 3 and greated than 4.
    // Either 3 or 4.
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s [root_process] [process_id] [Option: dc|ds|id|lg|lz|df|op|gc|do|so|pz|sk|st|dt|rp]\n", argv[0]);
        exit(EXIT_FAILURE); // EXIT_FAILURE = 1, represent standard failure status code when a program terminates due to an error.
    }

    if(!is_number(argv[1]) || !is_number(argv[2]))
    {
        printf("root_process and process_id must be a number.\n");
        fprintf(stderr, "Usage: %s [root_process] [process_id] [Option: dc|ds|id|lg|lz|df|op|gc|do|so|pz|sk|st|dt|rp]\n", argv[0]);
        exit(0);
    }

    int root_process = atoi(argv[1]);
    int process_id = atoi(argv[2]);

    if(argv[3] == NULL)
    {
        // If process_id is descendant of root_process
        if (is_descendant(root_process, process_id)) 
        {
            printf("%d %d\n", process_id, get_parent_processid(process_id));
            //printf("Process %d is a descendant of %d\n", process_id, root_process);
            exit(0);
        } 
        else    // If process_id is not descendant of root_process
            return 0;
    }
    // If argv[3] is any of the following options dc|ds|id|lg|lz|df|op|gc|do|so|pz|sk|st|dt|rp
    else if (!strcmp(argv[3],"-dc") || !strcmp(argv[3],"-ds") || !strcmp(argv[3],"-id") || !strcmp(argv[3],"-lg") || !strcmp(argv[3],"-lz") || !strcmp(argv[3],"-df") || !strcmp(argv[3],"-op") || !strcmp(argv[3],"-gc") || !strcmp(argv[3],"-do") || !strcmp(argv[3],"-so") || !strcmp(argv[3],"-pz") || !strcmp(argv[3],"-sk") || !strcmp(argv[3],"-st") || !strcmp(argv[3],"-dt") || !strcmp(argv[3],"-rp"))
    {
        if (!is_descendant(root_process, process_id)) 
        {
            printf("The process %d does not belong to the tree rooted at %d\n", process_id, root_process);
            return 0;
        }
        // else print nothing
        // This means correct option is given in cmd. And also process_id is descendant of the root_process.
    }
    else
    {
        fprintf(stderr, "Usage: %s [root_process] [process_id] [Option: dc|ds|id|lg|lz|df|op|gc|do|so|pz|sk|st|dt|rp]\n", argv[0]);
        exit(0);
    }
    

     // Exception for orphan processes
    if(!check_orphan(root_process))
    {   
        // Check if the processes belong to bash or not
        if (!belongs_to_bash_tree(root_process, process_id)) 
        {
            printf("Either root_process %d or process_id %d does not belong to any Bash process\n", root_process, process_id);
            return 0;
        }
    }
    

    // Option1: -dc
    // -dc: Count all descendents of process_id that are defunct or zombie
    // Check for "State: Z (zombie)" for zombie processes
    if (argv[3] && !strcmp(argv[3],"-dc")) // strcmp returns 0 on success
    {
        int defunct_count= count_zombie_process(process_id);
        printf("Number of defunct descendants of the process %d: %d\n", process_id, defunct_count);
        exit(0);
    }

    // Option2: -ds
    // Get all descendants of process_id
    pid_t descendants[MAX_PROCESSES];   // Array to store process id of all descendants
    int descendant_count = 0;
    find_descendants(process_id, descendants, &descendant_count);

    // Get immediate children of process_id
    pid_t direct_children[MAX_PROCESSES];   // Array to store process id of immediate descendants
    int child_count = 0;
    get_direct_children(process_id, direct_children, &child_count);

    // Handle -ds option (Non-direct Descendants)
    // lists the PIDs of all the non-direct descendants of process_id
    if (argv[3] && strcmp(argv[3], "-ds") == 0) 
    {   
        int flag=0;
        int buffer_pid[MAX_PROCESSES];
        int k=0;

        for (int i = 0; i < descendant_count; i++) 
        {
            int is_direct_child = 0;
            for (int j = 0; j < child_count; j++) 
            {
                if (descendants[i] == direct_children[j]) 
                {
                    is_direct_child = 1;
                    break;
                }
            }
            if (!is_direct_child) 
            {   
                flag=1;
                buffer_pid[k]= descendants[i];
                k++;
                //printf("%d\n", descendants[i]);
            }
        }
        
        if(flag)
        {
            //printf("Non-direct descendants of process %d:\n", process_id);
            for (int i = 0; i < k; i++) 
            {
                printf("%d\n", buffer_pid[i]);
            }
        }
        else
        {
            printf("No non-direct descendants.\n");
        }
        exit(0);
    }

    // Option3: -id
    // Handle -id option (Immediate Descendants)
    // lists the PIDs of all the immediate descendants of process_id
    if (argv[3] && strcmp(argv[3], "-id") == 0) 
    {
        // if no non-direct descendants exist
        if(child_count == 0)
        {
            printf("No direct descendants.\n");
            exit(0);
        }

        //printf("Immediate descendants of process %d:\n", process_id);
        for (int i = 0; i < child_count; i++)
        {
            printf("%d\n", direct_children[i]);
        }
        exit(0);
    }
    
    // Option4: -lg
    // lists the PIDs of all the sibling processes of process_id 
    if (argv[3] && strcmp(argv[3], "-lg") == 0) 
    {
        list_siblings(process_id, 0);   // Passing 0 means list all siblings of process_id

        // For debugging purpose
        // printf("sibling_count: %d\n", sibling_count);

        if(sibling_count == 0 )
        {
            printf("No sibling.\n");
            exit(0);
        }
        exit(0);
    } 
    
    // Option5: -lz
    // lists the PIDs of all the sibling processes of process_id that are defunct 
    if (argv[3] && strcmp(argv[3], "-lz") == 0) 
    {
        list_siblings(process_id, 1);   // Passing 1 as parameter means list only defunct (zombie) siblings of process_id

        // For debugging purpose
        // printf("sibling_count: %d\n", sibling_count);

        if(sibling_count == 0 )
        {
            printf("No defunct sibling.\n");
            exit(0);
        }
        exit(0);
    }
    
    // Option6: -df
    // Lists the PIDs of all descendents of process_id that are defunct
    if (argv[3] && strcmp(argv[3], "-df") == 0) 
    {
        if(count_zombie_process(process_id) == 0)
        {
            printf("No descendant zombie process/es.\n");
            exit(0);
        }

        //printf("Zombie descendants of process %d:\n", process_id);
        list_zombie_descendants(process_id); // Here I am not storing the process ids, instead I am directly checking and printing it.
        exit(0);
    }

    // Option7: -gc
    // lists the PIDs of all the grandchildren of process_id
    if (argv[3] && strcmp(argv[3], "-gc") == 0) 
        list_grandchildren(process_id);
    
    // Option8: -do
    // prints the status of the process_id (Defunct/ Not Defunct) 
    if (argv[3] && strcmp(argv[3], "-do") == 0) 
        check_defunct(process_id);
       
    // Option9: -pz
    //-pz: Kills the parents of all zombie process that are the descendants of proceed_id
    if (argv[3] &&  strcmp(argv[3], "-pz") == 0) 
       kill_zombie_parents(process_id);

    // Option10: -sk
    //-sk: All descendants of process_id are killed using SIGKILL
    if (argv[3] &&  strcmp(argv[3], "-sk") == 0) 
        send_signal_to_descendants(process_id, SIGKILL);

    // Option11: -st
    //-st: All descendants of process_id are stopped using SIGSTOP
    if (argv[3] &&  strcmp(argv[3], "-st") == 0) 
        send_signal_to_descendants(process_id, SIGSTOP);

    // Option12: -dt
    //-dt: All descendants of process_id currently stopped are continued using SIGCONT
    if (argv[3] &&  strcmp(argv[3], "-dt") == 0) 
        send_signal_to_descendants(process_id, SIGCONT);

    // Option13: -rp
    //-rp: root_process is killed using SIGKILL
    if (argv[3] &&  strcmp(argv[3], "-rp") == 0) 
        kill_root_process(root_process);

    return 0;
}
/*
End of main
*/
