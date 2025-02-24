/*
    fafl-poc v0.1
    An afl proxy for frida-based coverage-guided blackbox fuzzing.
    author: ax - github.com/ax

    Based on american fuzzy lop++ afl-proxy skeleton example
    from Marc Heuse <mh@mh-sec.de> which is licensed under
    the Apache License, Version 2.0. 
    You may obtain a copy of the License at:
    http://www.apache.org/licenses/LICENSE-2.0
    ---------------------------------------------------

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "frida-core.h"
#include "config.h"
#include "types.h"

#include <string.h>
#include <arpa/inet.h>

#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <semaphore.h>

#define SLEEP_MICROS 1000 

//u32 global_status=0x00;
u8 *__afl_area_ptr;

__thread u32 __afl_map_size = MAP_SIZE;

/* Error reporting to forkserver controller */

void send_forkserver_error(int error) {
  u32 status;
  if (!error || error > 0xffff) return;
  status = (FS_OPT_ERROR | FS_OPT_SET_ERROR(error));
  if (write(FORKSRV_FD + 1, (char *)&status, 4) != 4) return;
}

/* SHM setup. */
static void __afl_map_shm(void) {
  char *id_str = getenv(SHM_ENV_VAR);
  char *ptr;
  /* NOTE TODO BUG FIXME: if you want to supply a variable sized map then
     uncomment the following: */
  /*
  if ((ptr = getenv("AFL_MAP_SIZE")) != NULL) {

    u32 val = atoi(ptr);
    if (val > 0) __afl_map_size = val;
  }
  */

  if (__afl_map_size > MAP_SIZE) {
    if (__afl_map_size > FS_OPT_MAX_MAPSIZE) {
      fprintf(stderr,
              "Error: AFL++ tools *require* to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);
      if (id_str) {
        send_forkserver_error(FS_ERROR_MAP_SIZE);
        exit(-1);
      }
    } else {
      fprintf(stderr,
              "Warning: AFL++ tools will need to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);
    }
  }
  if (id_str) {

    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, 0, 0);

    if (__afl_area_ptr == (void *)-1) {
      send_forkserver_error(FS_ERROR_SHMAT);
      exit(1);
    }
    /* Write something into the bitmap so that the parent doesn't give up */
    __afl_area_ptr[0] = 1;
  }
}

static void __afl_start_forkserver(void) {
  u8  tmp[4] = {0, 0, 0, 0};
  u32 status = 0;
  if (__afl_map_size <= FS_OPT_MAX_MAPSIZE)
    status |= (FS_OPT_SET_MAPSIZE(__afl_map_size) | FS_OPT_MAPSIZE);
  if (status) status |= (FS_OPT_ENABLED);
  memcpy(tmp, &status, 4);
  /* Phone home and tell the parent that we're OK. */
  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;
}

static u32 __afl_next_testcase(u8 *buf, u32 max_len) {
  s32 status, res = 0xffffff;
  /* Wait for parent by reading from the pipe. Abort if read fails. */
  if (read(FORKSRV_FD, &status, 4) != 4) return 0;
  /* we have a testcase - read it */
  status = read(0, buf, max_len);
  /* report that we are starting the target */
  if (write(FORKSRV_FD + 1, &res, 4) != 4) return 0;
  return status;
}

static void __afl_end_testcase(int status) {
  //int status = 0xffffff;
  if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(1);
}

void log_to_file(const char *filename, const char *message) {
    // Open the file in append mode ("a")
    FILE *file = fopen(filename, "a");

    if (file == NULL) {
        // If the file couldn't be opened, print an error and return
        perror("Error opening log file");
        return;
    }
    // Write the message to the log file, followed by a newline
    fprintf(file, "%s\n", message);
    // Close the file after writing
    fclose(file);
}

void log_bin_to_file(const char *filename, const void *data, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Error opening log file");
        return;
    }
    size_t written = fwrite(data, 1, size, file);
    if (written != size) {
        perror("Error writing to log file");
    }
    fclose(file);
}

static void on_message(FridaScript *script __attribute__((unused)),
                       const gchar *message,
                       GBytes *data,
                       gpointer user_data) {
    fprintf(stderr,"Message from script: %s\n", message);
   // fflush(stderr);
  //  const char *search_str = "CRASH";
  //  if (strstr(message, search_str)) {
  //      printf("The message contains the string: %s\n", search_str);
  //      global_status=0xb;
  //  }
}

void replace_first_line(const char *filename, const char *new_line) {
    FILE *file = fopen(filename, "r+");
    if (!file) {
        perror("Error opening file");
        return;
    }

    // Buffer to hold file content
    char *file_content = NULL;
    size_t file_size = 0;

    // Read the entire file into memory
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    rewind(file);

    file_content = (char *)malloc(file_size + 1);
    if (!file_content) {
        perror("Error allocating memory");
        fclose(file);
        return;
    }
    fread(file_content, 1, file_size, file);
    file_content[file_size] = '\0'; // Null-terminate the content

    // Find the end of the first line
    char *newline_pos = strchr(file_content, '\n');
    if (newline_pos) {
        // Write the new first line
        fseek(file, 0, SEEK_SET);
        fprintf(file, "%s\n", new_line);

        // Write the rest of the content
        fputs(newline_pos + 1, file);
    } else {
        // If there's no newline, just replace the whole file
        fseek(file, 0, SEEK_SET);
        fprintf(file, "%s", new_line);
    }

    // Truncate the file in case the new content is shorter
    fflush(file);
    ftruncate(fileno(file), ftell(file));

    // Cleanup
    free(file_content);
    fclose(file);
}

int send_tcp_test_case_to_target(uint8_t* buf, uint32_t len, const char* server_ip, uint16_t server_port) {
    int status;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    status=0;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        perror("Socket creation failed");
        usleep(SLEEP_MICROS);
    }
    if(connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        close(sock);
        usleep(SLEEP_MICROS);
    }
    send(sock, buf, len, 0); 
    close(sock);
    usleep(SLEEP_MICROS);
    return status;
}


int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <frida-server-addr> <pid> <script_path>\n", argv[0]);
        return 1;
    }
    /* This is were the testcase data is written into */
    u8  buf[1024];  // this is the maximum size for a test case! set it!
    s32 len;
    u32 status=0x00;
    /* here you specify the map size you need that you are reporting to
       afl-fuzz.  Any value is fine as long as it can be divided by 32. */
    __afl_map_size = MAP_SIZE;  // default is 65536
    GError *error = NULL;
    FridaDeviceManager *manager;
    FridaDevice *device;
    FridaSession *session;
    FridaScript *script;

    struct shm_fafl_data {
        uint8_t *afl_area_ptr;
        sem_t *sem;
        u32 *crash_flag;
    };

    printf("Try to sync.....................");
    // Define a key for the shared memory segment (use a unique value)
    key_t key = ftok("shmfile", 65);  // "shmfile" is a file that exists on disk
    if (key == -1) {
        perror("ftok failed");
        exit(1);
    }
    // Allocate shared memory using shmget
    //int shm_id_sem = shmget(key, sizeof(shm_fafl_data), IPC_CREAT | 0666);  // Size of memory = size of sem_t
    //int shm_id_sem = shmget(key, sizeof(sem_t), IPC_CREAT | 0666);  // Size of memory = size of sem_t
    int shm_id_sem = shmget(key, 256, IPC_CREAT | 0666);  // Size of memory = size of sem_t
    if (shm_id_sem == -1) {
        perror("shmget failed");
        exit(1);
    }
    // struct smh_fafl_data *fafl_data = (struct shm_fafl_data*) shmat(shm_id_sem, NULL, 0);
    // Attach the shared memory segment to the process's address space
    sem_t *sem = (sem_t *) shmat(shm_id_sem, NULL, 0);
    if (sem == (sem_t *) -1) {
        perror("sem shmat failed");
        exit(1);
    }
    // Initialize the semaphore in shm
    if (sem_init(sem, 1, 1) == -1) {  // 1 for shared between processes, 1 for initial value
        perror("sem_init failed");
        exit(1);
    }
    // Initialize semaphore and crash flag in shm


    printf("Crash shm...");
    // Define a key for the shared memory segment (use a unique value)
    key_t keycrash = ftok("crashshmfile", 66);  // "shmfile" is a file that exists on disk
    if (keycrash == -1) {
        perror("ftok failed");
        exit(1);
    }
    // Allocate shared memory using shmget
    //int shm_id_sem = shmget(key, sizeof(sem_t), IPC_CREAT | 0666);  // Size of memory = size of sem_t
    int shm_id_crash = shmget(keycrash, 32, IPC_CREAT | 0666);  // Size of memory = size of sem_t
    if (shm_id_crash == -1) {
        perror("crash shmget failed");
        exit(1);
    }
    // Attach the shared memory segment to the process's address space
    u32 *crash_flag = (u32 *) shmat(shm_id_crash, NULL, 0);
    if (crash_flag == (u32 *) -1) {
        perror("shmat failed");
        exit(1);
    }
    // Initialize the semaphore in shm
    *crash_flag = 0x00;


    char *id_str = getenv(SHM_ENV_VAR);
    fprintf(stderr,"GETENV SHM_ENV_VAR: %s \n",id_str);
    u32 shm_id = atoi(id_str);
    fprintf(stderr,"HEX GETENV SHM_ENV_VAR: %x \n",shm_id);
    const char *filename = argv[3]; 
    char new_line[128];
    snprintf(new_line, sizeof(new_line), "const shm_id = 0x%x;const sem_shm_id=0x%x;const crash_shm_id=0x%x;", shm_id, shm_id_sem, shm_id_crash);
    replace_first_line(filename, new_line);

    frida_init();
    manager = frida_device_manager_new();
    device = frida_device_manager_add_remote_device_sync(
       manager,
       argv[1],    // address (host:port)
       NULL,       // options
       NULL,       // cancellable
       &error
    );

    if (error != NULL) {
        printf("Failed to connect to remote device: %s\n", error->message);
        g_error_free(error);
        g_object_unref(manager);
        return 1;
    }

    gchar *device_name = frida_device_get_name(device);
    FridaDeviceType device_type = frida_device_get_dtype(device);
    printf("Connected to device: %s (Type: %d)\n", device_name, device_type);
    g_free(device_name);
    
    guint pid = (guint)atoi(argv[2]);
    
    session = frida_device_attach_sync(device, pid, NULL, NULL, &error);
    if (error != NULL) {
        printf("Failed to attach to process: %s\n", error->message);
        g_error_free(error);
        return 1;
    }
    
    FILE *fp = fopen(argv[3], "r");
    if (!fp) {
        printf("Failed to open script file: %s\n", strerror(errno));
        return 1;
    }
    
    fseek(fp, 0, SEEK_END);
    long script_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *script_source = malloc(script_size + 1);
    fread(script_source, 1, script_size, fp);
    script_source[script_size] = '\0';
    fclose(fp);

    FridaScriptOptions *options = frida_script_options_new();
    // CHECK which runtime
    // frida_script_options_set_name(options, "harness");
    frida_script_options_set_runtime(options, FRIDA_SCRIPT_RUNTIME_QJS);

    script = frida_session_create_script_sync(session, script_source, options, NULL, &error);
    if (error != NULL) {
        printf("Failed to create script: %s\n", error->message);
        g_error_free(error);
        return 1;
    }
    
    // Connect message handler
    g_signal_connect(script, "message", G_CALLBACK(on_message), NULL);
    
    frida_script_load_sync(script, NULL, &error);
    if (error != NULL) {
        printf("Failed to load script: %s\n", error->message);
        g_error_free(error);
        return 1;
    }

    printf("[fafl>] Script loaded successfully!!!!\n");

    /* then we initialize the shared memory map and start the forkserver */
    __afl_map_shm();
    __afl_start_forkserver();
    
    while((len = __afl_next_testcase(buf, sizeof(buf))) > 0) {
        if(len > 4){  

            status=send_tcp_test_case_to_target(buf,len,"127.0.0.1",8080);
            //printf("Waiting on semaphore...\n");
            if (sem_wait(sem) == -1) {
                perror("sem_wait failed");
                exit(1);
            }
            usleep(SLEEP_MICROS);
            //if (buf[0] == 0xff) __afl_area_ptr[1] = 1; else __afl_area_ptr[2] = 2;
            // CRASH DETECTED BY FRIDA Exception Handler
            if(*crash_flag !=0){
                status=0x0b;
                char *crash_file="CRASH.txt";
                log_bin_to_file(crash_file, buf,len);
                __afl_end_testcase(status);
                usleep(SLEEP_MICROS);
                pid_t parent_pid = getppid(); 
                //printf("Sending SIGINT to parent process (PID: %d)...\n", parent_pid);
                if (!kill(parent_pid, SIGINT) == 0) {
                    perror("Failed to send SIGINT");
                }
                sleep(0.5); // we will shorlty die
            }
        }
        /* report the test case is done and wait for the next */
        __afl_end_testcase(status);
    }//end WHILE
    // Cleanup
    g_object_unref(script);
    g_object_unref(session);
    g_object_unref(device);
    g_object_unref(manager);
    free(script_source);
    return 0;
}
