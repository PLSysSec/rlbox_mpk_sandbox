#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <setjmp.h>

static inline void my_wrpkru(unsigned int pkru)
{
  unsigned int eax = pkru;
  unsigned int ecx = 0;
  unsigned int edx = 0;

  asm volatile(".byte 0x0f,0x01,0xef\n\t" : : "a"(eax), "c"(ecx), "d"(edx));
}

int my_pkey_set(int pkey, unsigned long rights, unsigned long flags)
{
  unsigned int pkru = (rights << (2 * pkey));
  my_wrpkru(pkru);
  return 0;
}

int my_pkey_mprotect(void* ptr,
                  size_t size,
                  unsigned long orig_prot,
                  unsigned long pkey)
{
  return syscall(SYS_pkey_mprotect, ptr, size, orig_prot, pkey);
}

int my_pkey_alloc(void)
{
  return syscall(SYS_pkey_alloc, 0, 0);
}

int my_pkey_free(unsigned long pkey)
{
  return syscall(SYS_pkey_free, pkey);
}

#define errExit(msg)                                                           \
  do {                                                                         \
    perror("Error " msg);                                                               \
    exit(1);                                                                   \
  } while (0)

jmp_buf env;
int crash_occurred = 0;

static void sigsegv_handler(int sig, siginfo_t *si, void *unused)
{
    crash_occurred=1;
    longjmp(env, 1);
}

int main(void)
{
  int status;
  int pkey;
  int* buffer;
  int setjmp_val;

  /*
   *Allocate one page of memory
   */
  buffer = mmap(NULL,
                getpagesize(),
                PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_PRIVATE,
                -1,
                0);
  if (buffer == MAP_FAILED) {
    errExit("mmap");
  }

  /*
   * Put some random data into the page (still OK to touch)
   */
  *buffer = __LINE__;
  printf("buffer contains: %d\n", *buffer);

  /*
   * Allocate a protection key:
   */
  pkey = my_pkey_alloc();
  if (pkey == -1) {
    errExit("my_pkey_alloc");
  }

  /*
   * Disable access to any memory with "pkey" set,
   * even though there is none right now
   */
  status = my_pkey_set(pkey, PKEY_DISABLE_ACCESS, 0);
  if (status) {
    errExit("my_pkey_set");
  }

  /*
   * Set the protection key on "buffer".
   * Note that it is still read/write as far as mprotect() is
   * concerned and the previous my_pkey_set() overrides it.
   */
  status = my_pkey_mprotect(buffer, getpagesize(), PROT_READ | PROT_WRITE, pkey);
  if (status == -1) {
    errExit("my_pkey_mprotect");
  }

  printf("about to read buffer again...\n");

  struct sigaction sa;

  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = sigsegv_handler;
  if (sigaction(SIGSEGV, &sa, NULL) == -1) {
    errExit("sigaction");
  }

  setjmp_val = setjmp (env);
  if (!setjmp_val) {
    /*
    * This will crash, because we have disallowed access
    */
    printf("buffer contains: %d\n", *buffer);
  } else {
    if (!crash_occurred) {
        errExit("crash did not occur as expected");
    }
  }

  status = my_pkey_free(pkey);
  if (status == -1) {
    errExit("my_pkey_free");
  }

  return 0;
}
